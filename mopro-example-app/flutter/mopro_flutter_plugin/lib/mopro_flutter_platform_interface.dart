import 'dart:typed_data';

import 'package:mopro_flutter/mopro_types.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'mopro_flutter_method_channel.dart';

abstract class MoproFlutterPlatform extends PlatformInterface {
  /// Constructs a MoproFlutterPlatform.
  MoproFlutterPlatform() : super(token: _token);

  static final Object _token = Object();

  static MoproFlutterPlatform _instance = MethodChannelMoproFlutter();

  /// The default instance of [MoproFlutterPlatform] to use.
  ///
  /// Defaults to [MethodChannelMoproFlutter].
  static MoproFlutterPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [MoproFlutterPlatform] when
  /// they register themselves.
  static set instance(MoproFlutterPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String> crescentInitializeCache(
    String schemeName,
    CrescentAssetBundle assetBundle,
  ) {
    throw UnimplementedError('crescentInitializeCache() has not been implemented.');
  }

  Future<String> crescentProve(
    String cacheId,
    String jwtToken,
    String issuerPem,
    String configJson,
    String? devicePubPem,
  ) {
    throw UnimplementedError('crescentProve() has not been implemented.');
  }

  Future<String> crescentShow(
    String cacheId,
    String clientStateB64,
    String proofSpecJson,
    String? presentationMessage,
    String? devicePrvPem,
  ) {
    throw UnimplementedError('crescentShow() has not been implemented.');
  }

  Future<String> crescentVerify(
    String cacheId,
    String showProofB64,
    String proofSpecJson,
    String? presentationMessage,
    String issuerPem,
    String configJson,
  ) {
    throw UnimplementedError('crescentVerify() has not been implemented.');
  }

  Future<void> crescentCleanupCache(
    String cacheId,
  ) {
    throw UnimplementedError('crescentCleanupCache() has not been implemented.');
  }

  Future<List<TimingResult>> crescentGetTimings(
    String cacheId,
  ) {
    throw UnimplementedError('crescentGetTimings() has not been implemented.');
  }

  Future<void> crescentResetTimings(
    String cacheId,
  ) {
    throw UnimplementedError('crescentResetTimings() has not been implemented.');
  }

  Future<TimingResult?> crescentGetLatestTiming(
    String cacheId,
    String operation,
  ) {
    throw UnimplementedError('crescentGetLatestTiming() has not been implemented.');
  }
}
