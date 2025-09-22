import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:mopro_flutter/mopro_types.dart';

import 'mopro_flutter_platform_interface.dart';

/// An implementation of [MoproFlutterPlatform] that uses method channels.
class MethodChannelMoproFlutter extends MoproFlutterPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('mopro_flutter');

  @override
  Future<String> crescentInitializeCache(
    String schemeName,
    CrescentAssetBundle assetBundle,
  ) async {
    final result = await methodChannel.invokeMethod<String>('crescentInitializeCache', {
      'schemeName': schemeName,
      'mainWasm': assetBundle.mainWasm,
      'mainR1cs': assetBundle.mainR1cs,
      'groth16Pvk': assetBundle.groth16Pvk,
      'groth16Vk': assetBundle.groth16Vk,
      'proverParams': assetBundle.proverParams,
      'rangePk': assetBundle.rangePk,
      'rangeVk': assetBundle.rangeVk,
      'ioLocations': assetBundle.ioLocations,
    });
    return result ?? '';
  }

  @override
  Future<String> crescentProve(
    String cacheId,
    String jwtToken,
    String issuerPem,
    String configJson,
    String? devicePubPem,
  ) async {
    final result = await methodChannel.invokeMethod<String>('crescentProve', {
      'cacheId': cacheId,
      'jwtToken': jwtToken,
      'issuerPem': issuerPem,
      'configJson': configJson,
      'devicePubPem': devicePubPem,
    });
    return result ?? '';
  }

  @override
  Future<String> crescentShow(
    String cacheId,
    String clientStateB64,
    String proofSpecJson,
    String? presentationMessage,
    String? devicePrvPem,
  ) async {
    final result = await methodChannel.invokeMethod<String>('crescentShow', {
      'cacheId': cacheId,
      'clientStateB64': clientStateB64,
      'proofSpecJson': proofSpecJson,
      'presentationMessage': presentationMessage,
      'devicePrvPem': devicePrvPem,
    });
    return result ?? '';
  }

  @override
  Future<String> crescentVerify(
    String cacheId,
    String showProofB64,
    String proofSpecJson,
    String? presentationMessage,
    String issuerPem,
    String configJson,
  ) async {
    final result = await methodChannel.invokeMethod<String>('crescentVerify', {
      'cacheId': cacheId,
      'showProofB64': showProofB64,
      'proofSpecJson': proofSpecJson,
      'presentationMessage': presentationMessage,
      'issuerPem': issuerPem,
      'configJson': configJson,
    });
    return result ?? '';
  }

  @override
  Future<void> crescentCleanupCache(
    String cacheId,
  ) async {
    await methodChannel.invokeMethod<void>('crescentCleanupCache', {
      'cacheId': cacheId,
    });
  }
}
