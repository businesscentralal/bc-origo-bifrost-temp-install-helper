namespace Origo.APP.Bifrost.TempInstallHelper;

using Origo.APP.CloudEvents;

/// <summary>
/// <c>Temp.InstallHelper.Access</c> — report / grant / revoke CE Full Access + SECURITY
/// for the CE-BIFROST install identity (issue #38).
/// </summary>
codeunit 50101 "Temp Install Helper Impl ori" implements "Cloud Event Msg Interface ori"
{
    Access = Internal;

    internal procedure IsEnabled(): Boolean
    begin
        exit(true);
    end;

    internal procedure GetFilterTableNo() FilterTableId: Integer
    begin
        exit(0);
    end;

    internal procedure GetDescription() Description: Text[250]
    begin
        exit('Report/grant/revoke CE Full Access ori + SECURITY for a BC user (temp install helper).');
    end;

    internal procedure GetMessageDirection() MessageDirection: Enum "Cloud Event Msg Direction ori"
    begin
        exit(Enum::"Cloud Event Msg Direction ori"::Inbound);
    end;

    internal procedure GetMessageHelpAsMarkdownDocument(var Argument: Record "CE Message Argument ori")
    var
        HelpBuilder: TextBuilder;
    begin
        HelpBuilder.AppendLine('# Temp.InstallHelper.Access');
        HelpBuilder.AppendLine('');
        HelpBuilder.AppendLine('Disposable helper for CE-BIFROST install (#38).');
        HelpBuilder.AppendLine('');
        HelpBuilder.AppendLine('## Request');
        HelpBuilder.AppendLine('```json');
        HelpBuilder.AppendLine('{ "data": { "action": "report|grant|revoke", "userName": "<BC User Name or empty>" } }');
        HelpBuilder.AppendLine('```');
        HelpBuilder.AppendLine('Top-level `action` / `userName` are also accepted.');
        HelpBuilder.AppendLine('');
        HelpBuilder.AppendLine('## Actions');
        HelpBuilder.AppendLine('- **report** — Access Control rows + legacy Field Access (10075489) read probe');
        HelpBuilder.AppendLine('- **grant** — insert CE Full Access ori (Tenant) + SECURITY (System) if missing');
        HelpBuilder.AppendLine('- **revoke** — delete exactly those two rows');
        Argument.SetResponseMarkdown(HelpBuilder.ToText());
    end;

    internal procedure ExecuteCloudEventTask(var Argument: Record "CE Message Argument ori")
    var
        Engine: Codeunit "Temp Install Helper Eng ori";
        RequestJson: JsonObject;
        DataObject: JsonObject;
        ResponseJson: JsonObject;
        ActionText: Text;
        UserName: Text;
        UnknownActionErr: Label 'Unknown action ''%1''. Expected report, grant, or revoke.', Comment = '%1 = action';
    begin
        Argument.AssertVersion1();
        if not Argument.AssertLicense() then
            exit;

        RequestJson := Argument.GetRequestJson();
        ParseRequest(RequestJson, ActionText, UserName);

        case LowerCase(ActionText) of
            'report':
                DataObject := Engine.ReportAccess(UserName);
            'grant':
                DataObject := Engine.GrantAccess(UserName);
            'revoke':
                DataObject := Engine.RevokeAccess(UserName);
            else
                Error(UnknownActionErr, ActionText);
        end;

        ResponseJson.Add('status', 'Success');
        ResponseJson.Add('action', LowerCase(ActionText));
        ResponseJson.Add('data', DataObject);
        Argument.SetResponseJson(ResponseJson);
        Argument."Content Type" := Argument.GetContentTypeJson();
    end;

    local procedure ParseRequest(RequestJson: JsonObject; var ActionText: Text; var UserName: Text)
    var
        DataToken: JsonToken;
        DataObject: JsonObject;
        Token: JsonToken;
        MissingActionErr: Label 'Request must include data.action (report|grant|revoke).';
    begin
        ActionText := '';
        UserName := '';

        if RequestJson.Get('data', DataToken) and DataToken.IsObject() then begin
            DataObject := DataToken.AsObject();
            if DataObject.Get('action', Token) and Token.IsValue() then
                ActionText := Token.AsValue().AsText();
            if DataObject.Get('userName', Token) and Token.IsValue() then
                UserName := Token.AsValue().AsText();
        end;

        // Fallback: top-level action / userName
        if ActionText = '' then
            if RequestJson.Get('action', Token) and Token.IsValue() then
                ActionText := Token.AsValue().AsText();
        if UserName = '' then
            if RequestJson.Get('userName', Token) and Token.IsValue() then
                UserName := Token.AsValue().AsText();

        if ActionText = '' then
            Error(MissingActionErr);
    end;
}
