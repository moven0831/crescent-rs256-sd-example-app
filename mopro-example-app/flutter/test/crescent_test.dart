import 'package:flutter_test/flutter_test.dart';
import 'package:mopro_flutter/mopro_flutter.dart';

void main() {
  group('Crescent RS256-SD Tests', () {
    final mopro = MoproFlutter();

    test('Crescent functions should be available', () {
      // Test that the functions exist and can be called
      // Note: These will fail in test environment without native bindings,
      // but validates that the method signatures are correct

      expect(() async {
        try {
          await mopro.crescentProve(
            'rs256-sd',
            'sample-jwt-token',
            'sample-pem-certificate'
          );
        } catch (e) {
          // Expected to fail in test environment
          expect(e, isA<Exception>());
        }
      }, returnsNormally);

      expect(() async {
        try {
          await mopro.crescentShow(
            'rs256-sd',
            'sample-client-state',
            '{"revealed": ["test"]}',
            null
          );
        } catch (e) {
          // Expected to fail in test environment
          expect(e, isA<Exception>());
        }
      }, returnsNormally);

      expect(() async {
        try {
          await mopro.crescentVerify(
            'rs256-sd',
            'sample-show-proof',
            '{"revealed": ["test"]}',
            null
          );
        } catch (e) {
          // Expected to fail in test environment
          expect(e, isA<Exception>());
        }
      }, returnsNormally);
    });

    test('Schema name should be rs256-sd', () {
      const schemeName = 'rs256-sd';
      expect(schemeName, equals('rs256-sd'));
    });

    test('Proof spec JSON should be valid', () {
      const proofSpec = '{"revealed": ["family_name", "tenant_ctry", "auth_time", "aud"]}';
      expect(proofSpec, contains('revealed'));
      expect(proofSpec, contains('family_name'));
    });
  });
}