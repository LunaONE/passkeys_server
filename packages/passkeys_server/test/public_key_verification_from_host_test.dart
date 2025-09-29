import 'dart:convert';

import 'package:passkeys_server/passkeys_server.dart';
import 'package:passkeys_server/src/util/internal.dart';
import 'package:test/test.dart';

void main() async {
  test('test key verification (from Chrome on macOS, Alg -7)', () async {
    final passkeys = Passkeys(
      config: PasskeysConfig(relyingPartyId: 'localhost'),
    );

    // const publicKey =
    //     'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDv4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg';
    const registrationAttestationObject =
        'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAELJkRhDywYoLi1XQ3LbGBgWlAQIDJiABIVggkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDsiWCD4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg';
    {
      // const userId = '6d8b443b-d1c6-4188-a6ee-2327abba31ed';
      const keyId = 'smRGEPLBiguLVdDctsYGBQ';
      // const publicKeyAlgorithm = '-7';
      const clientDataJSON =
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMjhHSVZ1dUNTXzVERzBMQTF0TnItMDEtcVd6TWY4UGZ5QlpOUVB0dFhxWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0';
      // const authenticatorData =
      //     'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAELJkRhDywYoLi1XQ3LbGBgWlAQIDJiABIVggkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDsiWCD4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg';
      const originalChallenge = '28GIVuuCS/5DG0LA1tNr+01+qWzMf8PfyBZNQPttXqY=';

      await expectLater(
        passkeys.verifyRegistration(
          keyId: base64.decode(padBase64(keyId)),
          // authenticatorData: base64.decode(padBase64(authenticatorData)),
          attestationObject:
              base64.decode(padBase64(registrationAttestationObject)),
          clientDataJSON: base64.decode(padBase64(clientDataJSON)),
          challenge: base64.decode(padBase64(originalChallenge)),
        ),
        completes,
      );
    }

    {
      const loginChallenge = 'tzDU2jDhlLCF3/hJSEFLZIi3M/xPf06twHtArTYQ5f8=';
      // const loginKeyId = 'smRGEPLBiguLVdDctsYGBQ';
      const authenticatorData =
          'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA';
      const clientDataJSON =
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHpEVTJqRGhsTENGM19oSlNFRkxaSWkzTV94UGYwNnR3SHRBclRZUTVmOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9';
      const signature =
          'MEUCIQDtgwZM-M-ilKkHwfOouoVb2pMuKwhzpmXFqT2yE6BEEAIgOl_OFgvmSf2fSfVe4NhgG6J2yWSp9eb1MvNt2xcU-CY';
      // const userHandle = 'bYtEO9HGQYim7iMnq7ox7Q';

      final challenge = base64.decode(padBase64(loginChallenge));

      await expectLater(
        passkeys.verifyLogin(
          registrationAttestationObject:
              base64.decode(padBase64(registrationAttestationObject)),
          authenticatorData: base64.decode(padBase64(authenticatorData)),
          clientDataJSON: base64.decode(padBase64(clientDataJSON)),
          signature: base64.decode(padBase64(signature)),
          challenge: challenge,
        ),
        completes,
      );
    }
  });

  test('test key verification (from Edge on Windows, Alg -257)', () async {
    final passkeys = Passkeys(
      config: PasskeysConfig(relyingPartyId: 'passkeys-server.lunaone.de'),
    );

    const registrationAttestationObject =
        'o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQBVfiUg1BaUf_CHkHTtfBcB_GDaV5JDqhM2JV-ASLM5oPYs3PYX5fa_jANlJ8_3tSK6ThQ6JPmGNRSgW9ezhVHxqgUm83ORJ9w56_9LqRExwMAK8Eorh39JrpXlnjdU9qnSxNcRZYXORrNjeOvTUN7QLDN0OQ3u9YD7e08WfJ-dp5XDXqCl15Vy3vCAyrvXnmsfYi4GnPLjJ8ybFDg6Hw9av9z9o5_YtAqYu2hx5L5_b6A6EW3IovO7LNlBSYvFrI-R4WBUUq3PYnaai9Y1-Ro_q9o2ghpn8pTlbXMGhZEx62oyaIufB0veZub_NahzafmRMhvV3GckL8JarQUEY31wY3ZlcmMyLjBjeDVjglkFtTCCBbEwggOZoAMCAQICECMDde6DJkyKmGbMva6-bzIwDQYJKoZIhvcNAQELBQAwPjE8MDoGA1UEAxMzUUNPTS1LRVlJRC1CQzI4MTU0NUU1MTgyQkEzQjNEQUJDQjEzNTI3NUNFNzlDNTRBNTE4MB4XDTI1MDkxNjA4MzYyN1oXDTMwMDUzMDE4NTIyNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIXX2FJBc0377ftnJrsN4b4E9BNKTrQdtmSpM_7zadBspn25z1K6WBI2pVzUp1207uLdCq8ky3ehShs2p1ZcpSRQRR8t3KxQQpTQ3xrbBU8SIf7aOoc3RGu9wVPJ0maxCbLWwddkYI9i4v9tytacY4em9524IIq2r-s-qrGsrrJvvl1wvfXeoC8dOl59ndS2-Sy6gJA7b_No_5rnCZiXAtbXYg90nlo3yS4BfTrmuNVpx0EQkfO8XesDI24s8-BumrrPkcqyqLPleptTOvlGql7C-ZlLKH1CMqrNJ2VTVEGbKglIprOcTKlLixQGick7-MiSSDDfyMLx6PEDkaMQPCkCAwEAAaOCAecwggHjMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDME4GA1UdEQEB_wREMEKkQDA-MRYwFAYFZ4EFAgEMC2lkOjUxNDM0RjREMQwwCgYFZ4EFAgIMATExFjAUBgVngQUCAwwLaWQ6MDAwOTAwMDAwHwYDVR0jBBgwFoAUIsL5ifSa-XhtEIAZRjCRwhbp84EwHQYDVR0OBBYEFGb4sxItQTBY3-pvtX2QLjIJjZMtMIGxBggrBgEFBQcBAQSBpDCBoTCBngYIKwYBBQUHMAKGgZFodHRwOi8vYXpjc3Byb2RldXNhaWtwdWJsaXNoLmJsb2IuY29yZS53aW5kb3dzLm5ldC9xY29tLWtleWlkLWJjMjgxNTQ1ZTUxODJiYTNiM2RhYmNiMTM1Mjc1Y2U3OWM1NGE1MTgtYy8xODc5YTJhMC00YjMzLTQ2NzItOGYwOS1iN2VhYzljNzBkMzkuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQB3ProL5nx3mCO6WmozO1OzTkN6FpjEhC0hx3H71Ps4NnN4rDNRPxzNyzMXPSeNZoPx3073VYzJHoYQM2jgVdxepOt5zmVeTburbzND9c7HZSnzjmTPLvwQOzA-dGES2pyEUSeVHDrd_qKnSuEoK46-AeRBcNPRIiyID-zwwVQ6nmEnnXLLr1p6967zjPAZhHpi_TwFRjg9NUNLK73M8kWU9hcfDjIrdV7lgbCtPKOWAx5xEbYIgxuyUQ_FqnfbGUe48S6FLOz652_65wIKeVjIgHdUpwKXGv2pnqC-b1wJYKxMBOgFRymqtuwB-qB7BgNC8zgPRcHXhmL1lxKAtP_NQiMeS-O7PPoJaAujU_aOaVrxO7d8Jd9fRVYsFUftf6ZtPEZXwO-bT_N54RSo1aoKmzl7JxifaU9OhjmbYjfxGL4HM4ru4-Q95u-gOg4naa2f7EgKarYkN_v4JjnWeFwW6gVXN23NqhhsHaBXpQ6MRTsvszPbuVZnIgVxChABOwHj0caLGL3QTizSpbkqIse8VOCWjHeTENxp4F2E3MRoRhoE2n8BXU_yye240PDJfwW6si3gXX_yUApAeEKT5U0S6MzCEs0Iq55gZZJmA7q0HwPRYOcv-lHhx2WSJB5sd8xs6hVZQklMTZrBLrYngV7Xfa-JXS_GTKioZeUn0Nm2NVkG7DCCBugwggTQoAMCAQICEzMAAAkXwL2xovtsJSMAAAAACRcwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yNDA1MzAxODUyMjZaFw0zMDA1MzAxODUyMjZaMD4xPDA6BgNVBAMTM1FDT00tS0VZSUQtQkMyODE1NDVFNTE4MkJBM0IzREFCQ0IxMzUyNzVDRTc5QzU0QTUxODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvKKelANk4DCFN-yp9e8sPTLyM4S8ljCTzQehBb71GKr1vFr-c1l7uJslwYTT1lRgO7oxhQMyIPGFh1VxtNiV5VRoK7Z2AlUbK6sE6wJvukXCZIRqf0ye9_6rQu573OWAUlxB7j3QiWAuSimdnitu5cryvyhTNo0hgYJdbMPJgsQjYyVqhwx_HbDYFbwUnyqLDerPLcxz9NqdyStBqeobVOxjVwpNZX76RKLdGv6Z2dmVBZTkkWWcvdUACGrRvGvOjqY1DG0PsIMC3KEKR7pogAbBIF6eUHC12GGYUUQ2kiio2mqttwbcsWsZcGvGquFuPLV5KrSVQnqH6MuHVWQcO-LP9LuiAPr6j39seHpgEIyj89hUB42LNPkEg6H-j8FiHd-Y6WMJ6Ya7blGNrTgJCWcHU76U1EFHcxDSQvZE__olWsi0bAE96Tlwnwl1NiaFqPX2Rj4kzGJ0MEs_SIpZW0Nny2kvb5eXe0wWEqfEGlQOHEaaYn5JGIdRq8karrVQCKEXninKx7TxuFG_eneUPnl5Kz1ySuQah_UKBUIZC81H01-HRXum6CUJLt5yAjwZHVwaBs-uJ6yiA7ja8DFO95suxUhoNTTkj-DM2-JlYZXM-5JO4y9mZinlTaENLV_Sn_14wHDbZWUSsYb94Xsr_5YkuuHLFyS5f6_NAKXbLNAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBQiwvmJ9Jr5eG0QgBlGMJHCFunzgTAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAJHbIhAP-5JrBsJMyo0QHlzcKd0I7nfdsXESgFNHtmbXaeqewWDE216WvSue8EiUGPNY4Un6kuMovKP9ByL6js7G2REY7JCSlWRryHyZTvAA5nwYbDqorbo1x_agb8LoIl4xnjfcfwQRUxUp4npztRp2Xvk77bYHRT0HaPt7cEgcmkzvMfRIP5KrpY65tpI3a06d7bX6racnxSZ3CKG6anVMUaMw5QMFNFdSBE07o3npji0g2k8iFLKv2KY6_td1ZepMvRMK32osfca2r5jqxWN81fjts_2EjdPAGao2n2fG5cFiEJF0mN3l3C8y6ovOoTO7k4SCt9z2s1ZtuevJa3wK7MmvTA6Ywr0DYJv2zDPFg3arOg5wKeBLOlx8MnfuEyNEwoxMTYQKyG-dhjUk34ygrGFPbiaJhd_CNOSUtu1sBJVF6XBStcsDAZT3J6Z3OiIvVZPOYeFUygckFP0aTbXGZQEi460FQzdcbKPjxynv3huYhTwqKkVMiLzUGS49r_Zl0JRed_rFnzOfMtj3jfDB4JgzsRIQ7C4V0OYforXHVRpG_I81-49Plmcuw-wM2jJl8D2jdFF-c4wYqhmyP8zJtkWRRWVRMlQdtf0Sl8TLuEnusJaAsdlu45ah_iykUEyUi4gGyzsjXtzeVSln2wnkiIJ-RLlE1xYwRqn2e_6-Z3B1YkFyZWFZATYAAQALAAYEMgAgy5RGec6q0HL7pTyoQlAbPhD4UA3R51OqQdz-XvxtqcsAEAAQCAAAAAAAAQCISDks0DQwHbnviYvzL8oEAfMO__SgsfO4ShZj22eUGHgonhTuer2MktQsuh9U4XEA-b12x51fl0SbuKLyqbnCjQ_YNHFXUxky3ZsP5vyHi0b0om7mDOwmzNye3a7GSBLd_VnKGyycubd0D7wCkv21M_Dur1BI-MdqZ-2iqWIo_xBB-H6kwgoKl8iWdEpXou7m4q-wdrYgVWF3ljzaTijjOUK8kecT59siJWojudHfwTC2n9jWGYgwdl2ACJIjearzrsCIMCaZT9MV57AjKgiLPCI1NCCqrKUw5bItanpVHb51hGk5ns850nM-ICdO0sJriE68O5CZDyLtWWfmCDlZaGNlcnRJbmZvWKH_VENHgBcAIgALgc9lw-5PHoMejjBIQ3sekDSmdfLR8OoCkcB3US4ayfQAFLFZdaceJG246e8QuUm7zX3eSn2dAAAAAAq74MdgvvWhVkIipwHzaZptO1-uEwAiAAtQSlbFPBE8AVoHkc803919E73MDVLU34eUKnAS2JeTYAAiAAvTEpMhshLibVy2PtSwu8HDxwyFxxItqxFTNi80MehwNGhhdXRoRGF0YVkBZzuQ64pI3Q3WT5JyJo4pMaZPb4yuYUjUpqYm4105EnbcRQAAAACd3RgXr1pGcqK5Pj3ZUACpACDNNTYD2-IJYEbw3TOT2SjGHk0oRLqD9hJ1DCCh8UQA5aQBAwM5AQAgWQEAiEg5LNA0MB2574mL8y_KBAHzDv_0oLHzuEoWY9tnlBh4KJ4U7nq9jJLULLofVOFxAPm9dsedX5dEm7ii8qm5wo0P2DRxV1MZMt2bD-b8h4tG9KJu5gzsJszcnt2uxkgS3f1ZyhssnLm3dA-8ApL9tTPw7q9QSPjHamftoqliKP8QQfh-pMIKCpfIlnRKV6Lu5uKvsHa2IFVhd5Y82k4o4zlCvJHnE-fbIiVqI7nR38Ewtp_Y1hmIMHZdgAiSI3mq867AiDAmmU_TFeewIyoIizwiNTQgqqylMOWyLWp6VR2-dYRpOZ7POdJzPiAnTtLCa4hOvDuQmQ8i7Vln5gg5WSFDAQAB';
    // Registration
    {
      // final userId =
      //     "[1, 153, 88, 120, 46, 153, 122, 181, 137, 193, 36, 181, 178, 158, 237, 114]";
      const keyId = 'zTU2A9viCWBG8N0zk9koxh5NKES6g_YSdQwgofFEAOU';
      // final publicKey =
      //     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiEg5LNA0MB2574mL8y_KBAHzDv_0oLHzuEoWY9tnlBh4KJ4U7nq9jJLULLofVOFxAPm9dsedX5dEm7ii8qm5wo0P2DRxV1MZMt2bD-b8h4tG9KJu5gzsJszcnt2uxkgS3f1ZyhssnLm3dA-8ApL9tTPw7q9QSPjHamftoqliKP8QQfh-pMIKCpfIlnRKV6Lu5uKvsHa2IFVhd5Y82k4o4zlCvJHnE-fbIiVqI7nR38Ewtp_Y1hmIMHZdgAiSI3mq867AiDAmmU_TFeewIyoIizwiNTQgqqylMOWyLWp6VR2-dYRpOZ7POdJzPiAnTtLCa4hOvDuQmQ8i7Vln5gg5WQIDAQAB";
      // final publicKeyAlgorithm = "-257";
      const clientDataJSON =
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWkR3bG83S1hLY1E1cEZZclFDU01YQ19YWWNlTHZQOHRuWVNRWGl5ZksyOCIsIm9yaWdpbiI6Imh0dHBzOi8vcGFzc2tleXMtc2VydmVyLmx1bmFvbmUuZGUiLCJjcm9zc09yaWdpbiI6ZmFsc2V9';
      // const authenticatorData =
      //     'O5DrikjdDdZPknImjikxpk9vjK5hSNSmpibjXTkSdtxFAAAAAJ3dGBevWkZyork-PdlQAKkAIM01NgPb4glgRvDdM5PZKMYeTShEuoP2EnUMIKHxRADlpAEDAzkBACBZAQCISDks0DQwHbnviYvzL8oEAfMO__SgsfO4ShZj22eUGHgonhTuer2MktQsuh9U4XEA-b12x51fl0SbuKLyqbnCjQ_YNHFXUxky3ZsP5vyHi0b0om7mDOwmzNye3a7GSBLd_VnKGyycubd0D7wCkv21M_Dur1BI-MdqZ-2iqWIo_xBB-H6kwgoKl8iWdEpXou7m4q-wdrYgVWF3ljzaTijjOUK8kecT59siJWojudHfwTC2n9jWGYgwdl2ACJIjearzrsCIMCaZT9MV57AjKgiLPCI1NCCqrKUw5bItanpVHb51hGk5ns850nM-ICdO0sJriE68O5CZDyLtWWfmCDlZIUMBAAE';
      const registrationChallenge =
          'ZDwlo7KXKcQ5pFYrQCSMXC/XYceLvP8tnYSQXiyfK28';

      await expectLater(
        passkeys.verifyRegistration(
          keyId: base64.decode(padBase64(keyId)),
          // authenticatorData: base64.decode(padBase64(authenticatorData)),
          attestationObject:
              base64.decode(padBase64(registrationAttestationObject)),
          clientDataJSON: base64.decode(padBase64(clientDataJSON)),
          challenge: base64.decode(padBase64(registrationChallenge)),
        ),
        completes,
      );
    }

    // Login
    {
      // final keyId =  'zTU2A9viCWBG8N0zk9koxh5NKES6g_YSdQwgofFEAOU';
      const clientDataJSON =
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMzFvTVB4OU5fVS1lUlozZmdZckptSFQzSEZVem5nd3VGZllheE80cE1BSSIsIm9yaWdpbiI6Imh0dHBzOi8vcGFzc2tleXMtc2VydmVyLmx1bmFvbmUuZGUiLCJjcm9zc09yaWdpbiI6ZmFsc2V9';
      const signature =
          'SJ9plyq5K3pdVcaT7LEuSwMnrMxmM8qFlgRfWcsc11Up8FRRrXziCAixSsOu06wcuI_CpaJ39puaCp_MXYsNcbQN2TXMEC9z4Uq-gdnWqctLVy5fQ1LGWx-szaJ2Dn2eRk4TPpkNwP8V01dhHqQ3GuCyF5aaVYR_6x7kY4F83KRLkjxVhYE3GqpRRvHNU_W4Dme2ZjWY51fctyH7N-yTmLwTPPYmLkoTfaI6h4xA-y0FLSeH30XHZcQAw9NDd5tyg67Ns3W6rLoXUHEG_dQtCmYmhVo0K-mxfnESFIp6YvDwQ_SFhnhL_N4LQTH5GL7mLsSVYiIXUcSkJIB0uaZyUw';
      const authenticatorData =
          'O5DrikjdDdZPknImjikxpk9vjK5hSNSmpibjXTkSdtwFAAAAAQ';
      // const publicKey =
      //     'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiEg5LNA0MB2574mL8y_KBAHzDv_0oLHzuEoWY9tnlBh4KJ4U7nq9jJLULLofVOFxAPm9dsedX5dEm7ii8qm5wo0P2DRxV1MZMt2bD-b8h4tG9KJu5gzsJszcnt2uxkgS3f1ZyhssnLm3dA-8ApL9tTPw7q9QSPjHamftoqliKP8QQfh-pMIKCpfIlnRKV6Lu5uKvsHa2IFVhd5Y82k4o4zlCvJHnE-fbIiVqI7nR38Ewtp_Y1hmIMHZdgAiSI3mq867AiDAmmU_TFeewIyoIizwiNTQgqqylMOWyLWp6VR2-dYRpOZ7POdJzPiAnTtLCa4hOvDuQmQ8i7Vln5gg5WQIDAQAB';

      const loginChallenge = '31oMPx9N/U+eRZ3fgYrJmHT3HFUzngwuFfYaxO4pMAI=';

      await expectLater(
        passkeys.verifyLogin(
          registrationAttestationObject:
              base64.decode(padBase64(registrationAttestationObject)),
          authenticatorData: base64.decode(padBase64(authenticatorData)),
          clientDataJSON: base64.decode(padBase64(clientDataJSON)),
          signature: base64.decode(padBase64(signature)),
          challenge: base64.decode(padBase64(loginChallenge)),
        ),
        completes,
      );
    }
  });
}
