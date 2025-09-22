import 'package:flutter_test/flutter_test.dart';
import 'package:mopro_flutter/mopro_flutter.dart';
import 'package:mopro_flutter/mopro_flutter_platform_interface.dart';
import 'package:mopro_flutter/mopro_flutter_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockMoproFlutterPlatform
    with MockPlatformInterfaceMixin
    implements MoproFlutterPlatform {
  @override
  Future<String> crescentProve(String schemeName, String jwtToken, String issuerPem) =>
      Future.value('mock-client-state-base64');

  @override
  Future<String> crescentShow(String schemeName, String clientStateB64, String proofSpecJson, String? presentationMessage) =>
      Future.value('mock-show-proof-base64');

  @override
  Future<String> crescentVerify(String schemeName, String showProofB64, String proofSpecJson, String? presentationMessage) =>
      Future.value('{"verified": true, "revealed_claims": {"family_name": "Doe", "tenant_ctry": "US"}}');

  // Stub implementations for unused methods
  @override
  Future<dynamic> generateCircomProof(String zkeyPath, String inputs, dynamic proofLib) =>
      throw UnimplementedError();

  @override
  Future<bool> verifyCircomProof(String zkeyPath, dynamic proof, dynamic proofLib) =>
      throw UnimplementedError();

  @override
  Future<dynamic> generateHalo2Proof(String srsPath, String pkPath, Map<String, List<String>> inputs) =>
      throw UnimplementedError();

  @override
  Future<bool> verifyHalo2Proof(String srsPath, String vkPath, dynamic proof, dynamic inputs) =>
      throw UnimplementedError();

  @override
  Future<dynamic> generateNoirProof(String circuitPath, String? srsPath, List<String> inputs, bool onChain, dynamic vk, bool lowMemoryMode) =>
      throw UnimplementedError();

  @override
  Future<bool> verifyNoirProof(String circuitPath, dynamic proof, bool onChain, dynamic vk, bool lowMemoryMode) =>
      throw UnimplementedError();

  @override
  Future<dynamic> getNoirVerificationKey(String circuitPath, String? srsPath, bool onChain, bool lowMemoryMode) =>
      throw UnimplementedError();
}

void main() {
  final MoproFlutterPlatform initialPlatform = MoproFlutterPlatform.instance;

  test('$MethodChannelMoproFlutter is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelMoproFlutter>());
  });

  test('Crescent functions work with mock platform', () async {
    MoproFlutter moproFlutterPlugin = MoproFlutter();
    MockMoproFlutterPlatform fakePlatform = MockMoproFlutterPlatform();
    MoproFlutterPlatform.instance = fakePlatform;

    // Test prove
    expect(
      await moproFlutterPlugin.crescentProve('rs256-sd', 'sample-jwt', 'sample-pem'),
      'mock-client-state-base64'
    );

    // Test show
    expect(
      await moproFlutterPlugin.crescentShow('rs256-sd', 'mock-client-state', '{"revealed": []}', null),
      'mock-show-proof-base64'
    );

    // Test verify
    expect(
      await moproFlutterPlugin.crescentVerify('rs256-sd', 'mock-show-proof', '{"revealed": []}', null),
      '{"verified": true, "revealed_claims": {"family_name": "Doe", "tenant_ctry": "US"}}'
    );
  });
}