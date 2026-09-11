namespace Origo.APP.Bifrost.TempInstallHelper.Test;

using Origo.APP.Bifrost.TempInstallHelper;
using System.Security.AccessControl;
using System.Security.User;
using System.TestLibraries.Utilities;

/// <summary>
/// Minimal unit tests for Temp Install Helper grant/revoke round-trip (issue #38).
/// </summary>
codeunit 50190 "Temp Install Helper Tests ori"
{
    Subtype = Test;
    TestPermissions = Disabled;

    var
        Assert: Codeunit "Library Assert";

    /// <summary>
    /// TC001: grant then revoke on the current user leaves the two target Access Control
    /// rows in the same present/absent state as before the round-trip.
    /// </summary>
    [Test]
    procedure TC001_GrantThenRevokeLeavesTargetRolesUnchanged()
    var
        Engine: Codeunit "Temp Install Helper Eng ori";
        GrantResult: JsonObject;
        RevokeResult: JsonObject;
        UserSecurityIdValue: Guid;
        BeforeCE: Boolean;
        BeforeSec: Boolean;
        AfterCE: Boolean;
        AfterSec: Boolean;
        SecondGrant: JsonObject;
        RowsInsertedToken: JsonToken;
        RowsInserted: JsonArray;
    begin
        // [GIVEN] Snapshot of the two target roles for the current user
        UserSecurityIdValue := UserSecurityId();
        Engine.TargetRolesPresent(UserSecurityIdValue, BeforeCE, BeforeSec);

        // Ensure a clean starting point for the grant under test: revoke first (idempotent)
        Engine.RevokeAccess('');
        Engine.TargetRolesPresent(UserSecurityIdValue, BeforeCE, BeforeSec);
        Assert.IsFalse(BeforeCE, 'Precondition: CE Full Access ori must be absent after cleanup revoke.');
        Assert.IsFalse(BeforeSec, 'Precondition: SECURITY must be absent after cleanup revoke.');

        // [WHEN] grant
        GrantResult := Engine.GrantAccess('');
        Assert.IsTrue(GrantResult.Get('rowsInserted', RowsInsertedToken), 'grant must return rowsInserted');
        RowsInserted := RowsInsertedToken.AsArray();
        Assert.AreEqual(2, RowsInserted.Count(), 'First grant must insert both rows.');

        // Idempotent second grant inserts nothing
        SecondGrant := Engine.GrantAccess('');
        Assert.IsTrue(SecondGrant.Get('rowsInserted', RowsInsertedToken), 'second grant must return rowsInserted');
        RowsInserted := RowsInsertedToken.AsArray();
        Assert.AreEqual(0, RowsInserted.Count(), 'Second grant must insert nothing.');

        // [WHEN] revoke
        RevokeResult := Engine.RevokeAccess('');
        Assert.IsTrue(RevokeResult.Get('rowsDeleted', RowsInsertedToken), 'revoke must return rowsDeleted');
        RowsInserted := RowsInsertedToken.AsArray();
        Assert.AreEqual(2, RowsInserted.Count(), 'Revoke must delete both rows.');

        // Idempotent second revoke deletes nothing
        RevokeResult := Engine.RevokeAccess('');
        Assert.IsTrue(RevokeResult.Get('rowsDeleted', RowsInsertedToken), 'second revoke must return rowsDeleted');
        RowsInserted := RowsInsertedToken.AsArray();
        Assert.AreEqual(0, RowsInserted.Count(), 'Second revoke must delete nothing.');

        // [THEN] target roles absent again (same as post-cleanup snapshot)
        Engine.TargetRolesPresent(UserSecurityIdValue, AfterCE, AfterSec);
        Assert.AreEqual(BeforeCE, AfterCE, 'CE Full Access ori presence must match pre-grant snapshot.');
        Assert.AreEqual(BeforeSec, AfterSec, 'SECURITY presence must match pre-grant snapshot.');
    end;

    /// <summary>
    /// TC002: report returns userName, userSecurityId, accessControlRows, legacyReadProbe.
    /// </summary>
    [Test]
    procedure TC002_ReportReturnsExpectedShape()
    var
        Engine: Codeunit "Temp Install Helper Eng ori";
        Report: JsonObject;
        Token: JsonToken;
        Probe: JsonObject;
    begin
        Report := Engine.ReportAccess('');
        Assert.IsTrue(Report.Get('userName', Token), 'report must include userName');
        Assert.IsTrue(Report.Get('userSecurityId', Token), 'report must include userSecurityId');
        Assert.IsTrue(Report.Get('accessControlRows', Token), 'report must include accessControlRows');
        Assert.IsTrue(Token.IsArray(), 'accessControlRows must be an array');
        Assert.IsTrue(Report.Get('legacyReadProbe', Token), 'report must include legacyReadProbe');
        Probe := Token.AsObject();
        Assert.IsTrue(Probe.Get('tableId', Token), 'probe must include tableId');
        Assert.AreEqual(10075489, Token.AsValue().AsInteger(), 'probe tableId must be 10075489');
        Assert.IsTrue(Probe.Get('ok', Token), 'probe must include ok');
    end;
}
