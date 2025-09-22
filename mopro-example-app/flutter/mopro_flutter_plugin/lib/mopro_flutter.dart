import 'dart:io';

import 'package:flutter/services.dart';
import 'package:mopro_flutter/mopro_types.dart';
import 'package:path_provider/path_provider.dart';

import 'mopro_flutter_platform_interface.dart';

class MoproFlutter {
  Future<String> copyAssetToFileSystem(String assetPath) async {
    // Load the asset as bytes
    final byteData = await rootBundle.load(assetPath);
    // Get the app's document directory (or other accessible directory)
    final directory = await getApplicationDocumentsDirectory();
    //Strip off the initial dirs from the filename
    assetPath = assetPath.split('/').last;

    final file = File('${directory.path}/$assetPath');

    // Write the bytes to a file in the file system
    await file.writeAsBytes(byteData.buffer.asUint8List());

    return file.path; // Return the file path
  }

  Future<String> crescentInitializeCache(String schemeName, CrescentAssetBundle assetBundle) async {
    return await MoproFlutterPlatform.instance.crescentInitializeCache(schemeName, assetBundle);
  }

  Future<String> crescentProve(String cacheId, String jwtToken, String issuerPem, String configJson, String? devicePubPem) async {
    return await MoproFlutterPlatform.instance.crescentProve(cacheId, jwtToken, issuerPem, configJson, devicePubPem);
  }

  Future<String> crescentShow(String cacheId, String clientStateB64, String proofSpecJson, String? presentationMessage, String? devicePrvPem) async {
    return await MoproFlutterPlatform.instance.crescentShow(cacheId, clientStateB64, proofSpecJson, presentationMessage, devicePrvPem);
  }

  Future<String> crescentVerify(String cacheId, String showProofB64, String proofSpecJson, String? presentationMessage, String issuerPem, String configJson) async {
    return await MoproFlutterPlatform.instance.crescentVerify(cacheId, showProofB64, proofSpecJson, presentationMessage, issuerPem, configJson);
  }

  Future<void> crescentCleanupCache(String cacheId) async {
    return await MoproFlutterPlatform.instance.crescentCleanupCache(cacheId);
  }

  Future<List<TimingResult>> crescentGetTimings(String cacheId) async {
    return await MoproFlutterPlatform.instance.crescentGetTimings(cacheId);
  }

  Future<void> crescentResetTimings(String cacheId) async {
    return await MoproFlutterPlatform.instance.crescentResetTimings(cacheId);
  }

  Future<TimingResult?> crescentGetLatestTiming(String cacheId, String operation) async {
    return await MoproFlutterPlatform.instance.crescentGetLatestTiming(cacheId, operation);
  }
}
