void main() async {
  // final storage = InMemoryPasskeyStorage();

  // {
  //   const userId = '6d8b443b-d1c6-4188-a6ee-2327abba31ed';
  //   const keyId = 'smRGEPLBiguLVdDctsYGBQ';
  //   const publicKey =
  //       'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDv4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg';
  //   const publicKeyAlgorithm = '-7';
  //   const clientDataJSON =
  //       'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMjhHSVZ1dUNTXzVERzBMQTF0TnItMDEtcVd6TWY4UGZ5QlpOUVB0dFhxWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0';
  //   const attestationObject =
  //       'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAELJkRhDywYoLi1XQ3LbGBgWlAQIDJiABIVggkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDsiWCD4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg';
  //   const authenticatorData =
  //       'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAELJkRhDywYoLi1XQ3LbGBgWlAQIDJiABIVggkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDsiWCD4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg';
  //   // const originalChallenge = '28GIVuuCS/5DG0LA1tNr+01+qWzMf8PfyBZNQPttXqY=';

  //   await storage.storeRegistration(
  //     userId: base64.decode(padBase64(userId)),
  //     keyId: base64.decode(padBase64(keyId)),
  //     clientDataJSON: base64.decode(padBase64(clientDataJSON)),
  //     publicKey: base64.decode(padBase64(publicKey)),
  //     publicKeyAlgorithm: int.parse(publicKeyAlgorithm),
  //     attestationObject: base64.decode(padBase64(attestationObject)),
  //     authenticatorData: base64.decode(padBase64(authenticatorData)),
  //     // TODO: Store challenge for later verification (at least when attestation object is used)
  //   );
  // }

  // {
  //   const loginChallenge = 'tzDU2jDhlLCF3/hJSEFLZIi3M/xPf06twHtArTYQ5f8=';
  //   const loginKeyId = 'smRGEPLBiguLVdDctsYGBQ';
  //   const authenticatorData =
  //       'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA';
  //   const clientDataJSON =
  //       'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHpEVTJqRGhsTENGM19oSlNFRkxaSWkzTV94UGYwNnR3SHRBclRZUTVmOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9';
  //   const signature =
  //       'MEUCIQDtgwZM-M-ilKkHwfOouoVb2pMuKwhzpmXFqT2yE6BEEAIgOl_OFgvmSf2fSfVe4NhgG6J2yWSp9eb1MvNt2xcU-CY';
  //   // const userHandle = 'bYtEO9HGQYim7iMnq7ox7Q';

  //   final loginId = Uint8ListUtil.random(8);

  //   // TODO: Should be login challenge
  //   await storage.storeRegistrationChallenge(
  //     userId: loginId,
  //     challenge: base64.decode(padBase64(loginChallenge)),
  //   );

  //   final passkeys = Passkeys(
  //     config: PasskeysConfig(relyingPartyId: 'localhost'),
  //     storage: storage,
  //   );

  //   await passkeys.verifyLogin(
  //     loginId: loginId,
  //     keyId: base64.decode(padBase64(loginKeyId)),
  //     authenticatorData: base64.decode(padBase64(authenticatorData)),
  //     clientDataJSON: base64.decode(padBase64(clientDataJSON)),
  //     signature: base64.decode(padBase64(signature)),
  //   );
  // }
}
