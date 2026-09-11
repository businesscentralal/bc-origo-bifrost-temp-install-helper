namespace Origo.APP.Bifrost.TempInstallHelper;

using Origo.APP.CloudEvents;

/// <summary>
/// Registers <c>Temp.InstallHelper.Access</c> on the legacy Cloud Events message-type enum.
/// Caption is Locked — the identifier is part of the wire contract (issue #38).
/// </summary>
enumextension 50100 "Temp Install Helper Msg ori" extends "Cloud Event Message Type ori"
{
    value(50100; "Temp.InstallHelper.Access")
    {
        Caption = 'Temp.InstallHelper.Access', Locked = true;
        Implementation = "Cloud Event Msg Interface ori" = "Temp Install Helper Impl ori";
    }
}
