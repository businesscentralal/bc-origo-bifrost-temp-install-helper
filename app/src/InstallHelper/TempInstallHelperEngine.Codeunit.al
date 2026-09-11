namespace Origo.APP.Bifrost.TempInstallHelper;

using System.Security.AccessControl;
using System.Security.User;

/// <summary>
/// Engine for <c>Temp.InstallHelper.Access</c>: report / grant / revoke the two Access Control
/// rows needed for CE-BIFROST Foundation install-time take-over (issue #38).
/// </summary>
codeunit 50102 "Temp Install Helper Eng ori"
{
    Access = Internal;
    Permissions = tabledata "Access Control" = RIMD;

    /// <summary>CE Full Access Role ID (Origo Cloud Events Core).</summary>
    procedure CEFullAccessRoleId(): Code[20]
    begin
        exit('CE Full Access ori');
    end;

    /// <summary>Origo Cloud Events Core app id.</summary>
    procedure CECoreAppId(): Guid
    begin
        exit('a629b897-7541-4562-bebb-c6122f15801c');
    end;

    /// <summary>SECURITY system permission set Role ID.</summary>
    procedure SecurityRoleId(): Code[20]
    begin
        exit('SECURITY');
    end;

    /// <summary>Empty Guid used as App ID for system-scoped SECURITY.</summary>
    procedure EmptyAppId(): Guid
    begin
        exit('00000000-0000-0000-0000-000000000000');
    end;

    /// <summary>Legacy Field Access table id used by the read probe.</summary>
    procedure FieldAccessTableId(): Integer
    begin
        exit(10075489);
    end;

    /// <summary>
    /// Resolves <paramref name="UserName"/> to User Security ID. Empty name → current user.
    /// </summary>
    /// <param name="UserName">BC User."User Name"; empty uses UserSecurityId().</param>
    /// <returns>User Security ID.</returns>
    procedure ResolveUserSecurityId(UserName: Text): Guid
    var
        User: Record User;
        UserNotFoundErr: Label 'User with User Name ''%1'' was not found.', Comment = '%1 = user name';
        CurrentUserName: Code[50];
    begin
        if UserName = '' then begin
            User.SetRange("User Security ID", UserSecurityId());
            if not User.FindFirst() then
                Error(UserNotFoundErr, Format(UserSecurityId()));
            exit(User."User Security ID");
        end;

        CurrentUserName := CopyStr(UserName, 1, MaxStrLen(User."User Name"));
        User.SetRange("User Name", CurrentUserName);
        if not User.FindFirst() then
            Error(UserNotFoundErr, UserName);
        exit(User."User Security ID");
    end;

    /// <summary>Returns the User Name for a User Security ID.</summary>
    procedure GetUserName(UserSecurityIdValue: Guid): Text
    var
        User: Record User;
    begin
        User.SetRange("User Security ID", UserSecurityIdValue);
        if User.FindFirst() then
            exit(User."User Name");
        exit(Format(UserSecurityIdValue));
    end;

    /// <summary>
    /// Builds the report JSON: user identity, Access Control rows, and legacy read probe.
    /// </summary>
    procedure ReportAccess(UserName: Text) Result: JsonObject
    var
        AccessControl: Record "Access Control";
        Rows: JsonArray;
        Row: JsonObject;
        UserSecurityIdValue: Guid;
    begin
        UserSecurityIdValue := ResolveUserSecurityId(UserName);
        Result.Add('userName', GetUserName(UserSecurityIdValue));
        Result.Add('userSecurityId', Format(UserSecurityIdValue));

        AccessControl.SetRange("User Security ID", UserSecurityIdValue);
        if AccessControl.FindSet() then
            repeat
                Clear(Row);
                Row.Add('roleId', AccessControl."Role ID");
                Row.Add('companyName', AccessControl."Company Name");
                Row.Add('scope', Format(AccessControl.Scope));
                Row.Add('scopeValue', AccessControl.Scope);
                Row.Add('appId', Format(AccessControl."App ID"));
                Rows.Add(Row);
            until AccessControl.Next() = 0;
        Result.Add('accessControlRows', Rows);
        Result.Add('legacyReadProbe', BuildLegacyReadProbe());
    end;

    /// <summary>
    /// Inserts the two target Access Control rows if missing. Idempotent.
    /// </summary>
    procedure GrantAccess(UserName: Text) Result: JsonObject
    var
        AccessControl: Record "Access Control";
        RowsInserted: JsonArray;
        UserSecurityIdValue: Guid;
    begin
        UserSecurityIdValue := ResolveUserSecurityId(UserName);
        Result.Add('userName', GetUserName(UserSecurityIdValue));
        Result.Add('userSecurityId', Format(UserSecurityIdValue));

        if InsertAccessControlIfMissing(
            UserSecurityIdValue, CEFullAccessRoleId(), '',
            AccessControl.Scope::Tenant, CECoreAppId())
        then
            RowsInserted.Add(DescribeRow(CEFullAccessRoleId(), '', 'Tenant', CECoreAppId()));

        if InsertAccessControlIfMissing(
            UserSecurityIdValue, SecurityRoleId(), '',
            AccessControl.Scope::System, EmptyAppId())
        then
            RowsInserted.Add(DescribeRow(SecurityRoleId(), '', 'System', EmptyAppId()));

        Result.Add('rowsInserted', RowsInserted);
    end;

    /// <summary>
    /// Deletes exactly the two target Access Control rows. Idempotent.
    /// </summary>
    procedure RevokeAccess(UserName: Text) Result: JsonObject
    var
        AccessControl: Record "Access Control";
        RowsDeleted: JsonArray;
        UserSecurityIdValue: Guid;
    begin
        UserSecurityIdValue := ResolveUserSecurityId(UserName);
        Result.Add('userName', GetUserName(UserSecurityIdValue));
        Result.Add('userSecurityId', Format(UserSecurityIdValue));

        if DeleteAccessControlExact(
            UserSecurityIdValue, CEFullAccessRoleId(), '',
            AccessControl.Scope::Tenant, CECoreAppId())
        then
            RowsDeleted.Add(DescribeRow(CEFullAccessRoleId(), '', 'Tenant', CECoreAppId()));

        if DeleteAccessControlExact(
            UserSecurityIdValue, SecurityRoleId(), '',
            AccessControl.Scope::System, EmptyAppId())
        then
            RowsDeleted.Add(DescribeRow(SecurityRoleId(), '', 'System', EmptyAppId()));

        Result.Add('rowsDeleted', RowsDeleted);
    end;

    /// <summary>
    /// Snapshot of whether the two target roles exist for the user (for unit tests).
    /// </summary>
    procedure TargetRolesPresent(UserSecurityIdValue: Guid; var CEFullPresent: Boolean; var SecurityPresent: Boolean)
    var
        AccessControl: Record "Access Control";
    begin
        CEFullPresent := AccessControl.Get(
            UserSecurityIdValue, CEFullAccessRoleId(), '',
            AccessControl.Scope::Tenant, CECoreAppId());
        SecurityPresent := AccessControl.Get(
            UserSecurityIdValue, SecurityRoleId(), '',
            AccessControl.Scope::System, EmptyAppId());
    end;

    local procedure InsertAccessControlIfMissing(
        UserSecurityIdValue: Guid; RoleId: Code[20]; CompanyName: Text[30];
        Scope: Option System,Tenant; AppId: Guid): Boolean
    var
        AccessControl: Record "Access Control";
    begin
        if AccessControl.Get(UserSecurityIdValue, RoleId, CompanyName, Scope, AppId) then
            exit(false);

        AccessControl.Init();
        AccessControl."User Security ID" := UserSecurityIdValue;
        AccessControl."Role ID" := RoleId;
        AccessControl."Company Name" := CompanyName;
        AccessControl.Scope := Scope;
        AccessControl."App ID" := AppId;
        AccessControl.Insert(true);
        exit(true);
    end;

    local procedure DeleteAccessControlExact(
        UserSecurityIdValue: Guid; RoleId: Code[20]; CompanyName: Text[30];
        Scope: Option System,Tenant; AppId: Guid): Boolean
    var
        AccessControl: Record "Access Control";
    begin
        if not AccessControl.Get(UserSecurityIdValue, RoleId, CompanyName, Scope, AppId) then
            exit(false);
        AccessControl.Delete(true);
        exit(true);
    end;

    local procedure DescribeRow(RoleId: Code[20]; CompanyName: Text[30]; ScopeText: Text; AppId: Guid) Row: JsonObject
    begin
        Row.Add('roleId', RoleId);
        Row.Add('companyName', CompanyName);
        Row.Add('scope', ScopeText);
        Row.Add('appId', Format(AppId));
    end;

    local procedure BuildLegacyReadProbe() Probe: JsonObject
    var
        CountValue: Integer;
        ErrorText: Text;
        Opened: Boolean;
    begin
        Probe.Add('tableId', FieldAccessTableId());
        Opened := false;
        CountValue := 0;
        ErrorText := '';

        if TryOpenAndCount(FieldAccessTableId(), CountValue) then
            Opened := true
        else
            ErrorText := GetLastErrorText();

        Probe.Add('ok', Opened);
        if Opened then
            Probe.Add('count', CountValue)
        else
            if ErrorText <> '' then
                Probe.Add('error', ErrorText)
            else
                Probe.Add('error', 'RecordRef.Open failed');
    end;

    [TryFunction]
    local procedure TryOpenAndCount(TableId: Integer; var CountValue: Integer)
    var
        RecRef: RecordRef;
    begin
        RecRef.Open(TableId);
        CountValue := RecRef.Count();
        RecRef.Close();
    end;
}
