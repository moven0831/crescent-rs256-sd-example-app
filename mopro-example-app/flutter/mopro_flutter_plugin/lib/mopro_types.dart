import 'dart:typed_data';

// Minimal types for Crescent RS256-SD functionality
// The Crescent functions work with String inputs and outputs,
// so we don't need the complex proof types from other systems

/// Asset bundle for efficient mobile caching
class CrescentAssetBundle {
  final Uint8List mainWasm;
  final Uint8List mainR1cs;
  final Uint8List groth16Pvk;
  final Uint8List groth16Vk;
  final Uint8List proverParams;
  final Uint8List rangePk;
  final Uint8List rangeVk;
  final String ioLocations;

  CrescentAssetBundle({
    required this.mainWasm,
    required this.mainR1cs,
    required this.groth16Pvk,
    required this.groth16Vk,
    required this.proverParams,
    required this.rangePk,
    required this.rangeVk,
    required this.ioLocations,
  });
}

class CrescentResult {
  final String data;
  final DateTime timestamp;

  CrescentResult(this.data) : timestamp = DateTime.now();

  @override
  String toString() {
    return "CrescentResult(data: $data, timestamp: $timestamp)";
  }
}

class CrescentException implements Exception {
  final String message;
  final String? details;

  CrescentException(this.message, [this.details]);

  @override
  String toString() {
    return details != null
        ? "CrescentException: $message - $details"
        : "CrescentException: $message";
  }
}