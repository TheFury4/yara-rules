import "pe"

rule Attune_Myla {
    meta:
        author = "Emanuele Furina"
        description = "Attune_Myla spyware"
        date = "2024-01-10"
    strings:
        $url1 = "http://tempuri.org/GetAlphaIntegrationData"
        $url2 = "http://tempuri.org/GetPatientDetailforSSDW"
        $url3 = "http://tempuri.org/GetTestCodesForBarCodes"
        $url4 = "http://tempuri.org/GetBidirectionalBarCodes"
        $url5 = "http://tempuri.org/InsertInvIntegrationResult"
        $url6 = "http://tempuri.org/UpdateAlphaIntegrationData"
        $url7 = "http://1.6.30.77/Metropolis_Staging/Integrationservices.asmx"
        $action1 = "Action http://tempuri.org/SetMPPSStatusT"
        $action2 = "Action&http://tempuri.org/GetDeviceImportDataT"
        $action3 = "Action&http://tempuri.org/GetModalityWorkListT"
        $action4 = "Action&http://tempuri.org/OrderInvestigationsT"
        $action5 = "Action*http://tempuri.org/GetAlphaIntegrationDataT"
        $action6 = "Action*http://tempuri.org/GetTestCodesForBarCodesT"
        $action7 = "Action+http://tempuri.org/GetBidirectionalBarCodesT"
        $action8 = "Action,http://tempuri.org/InsertInvestigationResultT"
        $action9 = "Action-http://tempuri.org/GetDeviceInvestigationDataT"
        $action10 = "Action-http://tempuri.org/InsertInvIntegrationResultT"
        $action11 = "Action-http://tempuri.org/UpdateAlphaIntegrationDataT"
        $action12 = "Action.http://tempuri.org/UpdateBidirectionalBarCodesT"
        $action13 = "Action/http://tempuri.org/InsertVitekIntegrationResultT"
        $action14 = "Action0http://tempuri.org/InsertDeviceInvestigationDataT"
        $action15 = "Action1http://tempuri.org/InvBidirectionalBarCodeDetailsT"
        $action16 = "Action2http://tempuri.org/ReceivePatientDetailsCaseSorterT"
        $action17 = "Action3http://tempuri.org/ResponsePatientDetailsCaseSorterT"
        $action18 = "Action4http://tempuri.org/UpdateBidirectionalBarcodeDetailsT"
        $action19 = "Action;http://tempuri.org/GetPatientDetailForCaseSorterIntegrationT"
        $action20 = "ActionLhttp://tempuri.org/DeviceInsertCaseSorterReceiveBarcodeDetailsSampleTransferT"
    condition:
        any of ($url*) or any of ($action*)
}
