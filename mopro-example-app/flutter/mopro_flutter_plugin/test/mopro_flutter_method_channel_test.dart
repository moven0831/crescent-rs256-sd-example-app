import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mopro_flutter/mopro_flutter_method_channel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  MethodChannelMoproFlutter platform = MethodChannelMoproFlutter();
  const MethodChannel channel = MethodChannel('mopro_flutter');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      channel,
      (MethodCall methodCall) async {
        switch (methodCall.method) {
          case 'crescentProve':
            return 'mock-client-state';
          case 'crescentShow':
            return 'mock-show-proof';
          case 'crescentVerify':
            return '{"verified": true}';
          default:
            return 'mock-response';
        }
      },
    );
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('Crescent method channel calls', () async {
    expect(
      await platform.crescentProve('rs256-sd', 'sample-jwt', 'sample-pem'),
      'mock-client-state'
    );

    expect(
      await platform.crescentShow('rs256-sd', 'client-state', '{"revealed": []}', null),
      'mock-show-proof'
    );

    expect(
      await platform.crescentVerify('rs256-sd', 'show-proof', '{"revealed": []}', null),
      '{"verified": true}'
    );
  });
}
