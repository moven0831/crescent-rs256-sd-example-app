import 'package:flutter/services.dart';
import 'package:mopro_flutter/mopro_flutter.dart';
import 'package:mopro_flutter/mopro_types.dart';

/// Utility class for loading Crescent assets from Flutter bundle
class CrescentAssetLoader {
  static const String _assetBasePath = 'assets/crescent';

  /// Load all assets for a scheme into a CrescentAssetBundle
  static Future<CrescentAssetBundle> loadAssetBundle(String schemeName) async {
    final basePath = '$_assetBasePath/$schemeName';

    // Load binary assets
    final mainWasm = await rootBundle.load('$basePath/main.wasm');
    final mainR1cs = await rootBundle.load('$basePath/main_c.r1cs');
    final groth16Pvk = await rootBundle.load('$basePath/groth16_pvk.bin');
    final groth16Vk = await rootBundle.load('$basePath/groth16_vk.bin');
    final proverParams = await rootBundle.load('$basePath/prover_params.bin');
    final rangePk = await rootBundle.load('$basePath/range_pk.bin');
    final rangeVk = await rootBundle.load('$basePath/range_vk.bin');

    // Load text assets
    final ioLocations = await rootBundle.loadString('$basePath/io_locations.sym');

    // Create CrescentAssetBundle from loaded data
    return CrescentAssetBundle(
      mainWasm: mainWasm.buffer.asUint8List(),
      mainR1cs: mainR1cs.buffer.asUint8List(),
      groth16Pvk: groth16Pvk.buffer.asUint8List(),
      groth16Vk: groth16Vk.buffer.asUint8List(),
      proverParams: proverParams.buffer.asUint8List(),
      rangePk: rangePk.buffer.asUint8List(),
      rangeVk: rangeVk.buffer.asUint8List(),
      ioLocations: ioLocations,
    );
  }

  /// Load credential data (JWT token, configs, etc.)
  static Future<CrescentCredentials> loadCredentials(String schemeName) async {
    final basePath = '$_assetBasePath/$schemeName';

    final jwtToken = await rootBundle.loadString('$basePath/token.jwt');
    final issuerPem = await rootBundle.loadString('$basePath/issuer.pub');
    final configJson = await rootBundle.loadString('$basePath/config.json');
    final devicePubPem = await rootBundle.loadString('$basePath/device.pub');
    final devicePrvPem = await rootBundle.loadString('$basePath/device.prv');
    final proofSpecJson = await rootBundle.loadString('$basePath/proof_spec.json');

    return CrescentCredentials(
      jwtToken: jwtToken,
      issuerPem: issuerPem,
      configJson: configJson,
      devicePubPem: devicePubPem,
      devicePrvPem: devicePrvPem,
      proofSpecJson: proofSpecJson,
    );
  }
}

/// Data class for Crescent credential information
class CrescentCredentials {
  final String jwtToken;
  final String issuerPem;
  final String configJson;
  final String devicePubPem;
  final String devicePrvPem;
  final String proofSpecJson;

  CrescentCredentials({
    required this.jwtToken,
    required this.issuerPem,
    required this.configJson,
    required this.devicePubPem,
    required this.devicePrvPem,
    required this.proofSpecJson,
  });
}