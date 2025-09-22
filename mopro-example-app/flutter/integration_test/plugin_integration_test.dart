import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:mopro_flutter/mopro_flutter.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Crescent RS256-SD Integration Tests', () {
    testWidgets('Crescent plugin integration', (WidgetTester tester) async {
      final moproFlutter = MoproFlutter();

      // Test that the plugin is properly initialized
      // Note: These tests require actual Crescent binaries and test vectors
      // to be available in the mobile app environment

      expect(moproFlutter, isNotNull);

      // Add actual integration tests here when circuit assets are available
      // For now, just verify the plugin instance can be created
    });
  });
}
