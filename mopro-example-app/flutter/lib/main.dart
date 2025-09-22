import 'package:flutter/material.dart';
import 'package:mopro_flutter/mopro_flutter.dart';
import 'crescent_asset_loader.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Crescent RS256-SD (Cached)',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const CrescentApp(),
    );
  }
}

class CrescentApp extends StatefulWidget {
  const CrescentApp({super.key});

  @override
  State<CrescentApp> createState() => _CrescentAppState();
}

enum CrescentStep { prove, show, verify }

class _CrescentAppState extends State<CrescentApp> {
  final _moproFlutterPlugin = MoproFlutter();

  // UI State
  bool isProcessing = false;
  Exception? _error;
  CrescentStep currentStep = CrescentStep.prove;

  // Form Controllers
  final TextEditingController _presentationMessageController = TextEditingController();

  // Crescent State
  String? cacheId;
  String? clientState;
  String? showProof;
  String? verifyResult;

  // Cached credentials (loaded once)
  CrescentCredentials? _credentials;

  // Constants
  static const String schemeName = "rs256-sd";

  @override
  void initState() {
    super.initState();
    _initializeCache();
  }

  Future<void> _initializeCache() async {
    setState(() {
      isProcessing = true;
      _error = null;
    });

    try {
      // Load asset bundle and credentials
      final assetBundle = await CrescentAssetLoader.loadAssetBundle(schemeName);
      final credentials = await CrescentAssetLoader.loadCredentials(schemeName);

      // Initialize cache
      final newCacheId = await _moproFlutterPlugin.crescentInitializeCache(
        schemeName,
        assetBundle
      );

      setState(() {
        cacheId = newCacheId;
        _credentials = credentials;
      });
    } on Exception catch (e) {
      setState(() {
        _error = e;
      });
    } finally {
      setState(() {
        isProcessing = false;
      });
    }
  }

  void _resetStepsFrom(CrescentStep step) {
    setState(() {
      if (step == CrescentStep.prove) {
        clientState = null;
        showProof = null;
        verifyResult = null;
      } else if (step == CrescentStep.show) {
        showProof = null;
        verifyResult = null;
      } else if (step == CrescentStep.verify) {
        verifyResult = null;
      }
    });
  }

  Future<void> _executeProve() async {
    if (cacheId == null || _credentials == null || isProcessing) {
      return;
    }

    setState(() {
      _error = null;
      isProcessing = true;
    });

    try {
      final result = await _moproFlutterPlugin.crescentProve(
        cacheId!,
        _credentials!.jwtToken,
        _credentials!.issuerPem,
        _credentials!.configJson,
        _credentials!.devicePubPem,
      );

      setState(() {
        clientState = result;
        currentStep = CrescentStep.show;
      });
    } on Exception catch (e) {
      setState(() {
        _error = e;
      });
    } finally {
      setState(() {
        isProcessing = false;
      });
    }
  }

  Future<void> _executeShow() async {
    if (cacheId == null || _credentials == null || clientState == null || isProcessing) {
      return;
    }

    setState(() {
      _error = null;
      isProcessing = true;
    });

    try {
      final result = await _moproFlutterPlugin.crescentShow(
        cacheId!,
        clientState!,
        _credentials!.proofSpecJson,
        _presentationMessageController.text.isNotEmpty
            ? _presentationMessageController.text
            : null,
        _credentials!.devicePrvPem,
      );

      setState(() {
        showProof = result;
        currentStep = CrescentStep.verify;
      });
    } on Exception catch (e) {
      setState(() {
        _error = e;
      });
    } finally {
      setState(() {
        isProcessing = false;
      });
    }
  }

  Future<void> _executeVerify() async {
    if (cacheId == null || _credentials == null || showProof == null || isProcessing) {
      return;
    }

    setState(() {
      _error = null;
      isProcessing = true;
    });

    try {
      final result = await _moproFlutterPlugin.crescentVerify(
        cacheId!,
        showProof!,
        _credentials!.proofSpecJson,
        _presentationMessageController.text.isNotEmpty
            ? _presentationMessageController.text
            : null,
        _credentials!.issuerPem,
        _credentials!.configJson,
      );

      setState(() {
        verifyResult = result;
      });
    } on Exception catch (e) {
      setState(() {
        _error = e;
      });
    } finally {
      setState(() {
        isProcessing = false;
      });
    }
  }

  @override
  void dispose() {
    // Cleanup cache when app closes
    if (cacheId != null) {
      _moproFlutterPlugin.crescentCleanupCache(cacheId!).catchError((e) {
        // Ignore cleanup errors
      });
    }
    _presentationMessageController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Crescent RS256-SD (Cached)'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Cache Status
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Cache Status',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      cacheId != null
                        ? 'Initialized: $cacheId'
                        : 'Initializing cache...',
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: cacheId != null ? Colors.green : Colors.orange,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Error Display
            if (_error != null)
              Card(
                color: Colors.red.shade100,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Error',
                        style: Theme.of(context).textTheme.titleMedium?.copyWith(
                          color: Colors.red.shade800,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        _error.toString(),
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Colors.red.shade700,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

            const SizedBox(height: 16),

            // Presentation Message Input
            TextField(
              controller: _presentationMessageController,
              decoration: const InputDecoration(
                labelText: 'Presentation Message (optional)',
                border: OutlineInputBorder(),
                helperText: 'Message to bind to the proof presentation',
              ),
            ),

            const SizedBox(height: 16),

            // Step Buttons
            Expanded(
              child: ListView(
                children: [
                  // Prove Step
                  _buildStepCard(
                    step: CrescentStep.prove,
                    title: '1. Prove Credential',
                    description: 'Generate client state from JWT credential',
                    buttonText: 'Generate Proof State',
                    onPressed: cacheId != null ? _executeProve : null,
                    result: clientState != null
                        ? 'Client state generated (${clientState!.length} chars)'
                        : null,
                  ),

                  const SizedBox(height: 12),

                  // Show Step
                  _buildStepCard(
                    step: CrescentStep.show,
                    title: '2. Create Show Proof',
                    description: 'Create presentation proof with selective disclosure',
                    buttonText: 'Create Show Proof',
                    onPressed: clientState != null && cacheId != null ? _executeShow : null,
                    result: showProof != null
                        ? 'Show proof created (${showProof!.length} chars)'
                        : null,
                  ),

                  const SizedBox(height: 12),

                  // Verify Step
                  _buildStepCard(
                    step: CrescentStep.verify,
                    title: '3. Verify Proof',
                    description: 'Verify the presentation proof and extract revealed claims',
                    buttonText: 'Verify Proof',
                    onPressed: showProof != null && cacheId != null ? _executeVerify : null,
                    result: verifyResult,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStepCard({
    required CrescentStep step,
    required String title,
    required String description,
    required String buttonText,
    required VoidCallback? onPressed,
    String? result,
  }) {
    final isCurrentStep = currentStep == step;
    final canExecute = onPressed != null && !isProcessing;

    return Card(
      elevation: isCurrentStep ? 4 : 1,
      color: isCurrentStep ? Theme.of(context).primaryColor.withOpacity(0.1) : null,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: isCurrentStep ? Theme.of(context).primaryColor : null,
                fontWeight: isCurrentStep ? FontWeight.bold : null,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              description,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 12),

            // Button and Reset
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: canExecute ? onPressed : null,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: isCurrentStep ? Theme.of(context).primaryColor : null,
                      foregroundColor: isCurrentStep ? Colors.white : null,
                    ),
                    child: isProcessing && isCurrentStep
                        ? const SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : Text(buttonText),
                  ),
                ),
                if (result != null) ...[
                  const SizedBox(width: 8),
                  IconButton(
                    onPressed: () => _resetStepsFrom(step),
                    icon: const Icon(Icons.refresh),
                    tooltip: 'Reset from this step',
                  ),
                ],
              ],
            ),

            // Result Display
            if (result != null) ...[
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.green.shade50,
                  border: Border.all(color: Colors.green.shade200),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  result.length > 200
                      ? '${result.substring(0, 200)}...'
                      : result,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Colors.green.shade800,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}