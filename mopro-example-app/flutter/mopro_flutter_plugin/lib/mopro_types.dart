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

/// Timing measurement for operations
class TimingResult {
  final String operation;
  final int durationMs;
  final int timestamp;

  TimingResult({
    required this.operation,
    required this.durationMs,
    required this.timestamp,
  });

  DateTime get dateTime => DateTime.fromMillisecondsSinceEpoch(timestamp * 1000);

  @override
  String toString() {
    return "TimingResult(operation: $operation, duration: ${durationMs}ms, timestamp: $timestamp)";
  }
}

/// Operation result with timing information
class OperationResult {
  final String result;
  final TimingResult timing;

  OperationResult({
    required this.result,
    required this.timing,
  });

  @override
  String toString() {
    return "OperationResult(result length: ${result.length}, timing: $timing)";
  }
}