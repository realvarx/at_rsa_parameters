import 'dart:convert';
import 'dart:io';

import 'package:archive/archive_io.dart';
import 'package:args/args.dart';
import 'package:at_rsa_parameters/cmd_parser.dart';
import 'package:at_rsa_parameters/constants.dart';
import 'package:crypton/crypton.dart' as crypton;
import 'package:encrypt/encrypt.dart';
import 'package:rsa_pkcs/rsa_pkcs.dart';

var parser = ArgParser();

Future<void> main(List<String> arguments) async {
  try {
    parser = CommandLineParser().getParser();
    if (arguments.length == 1 &&
        (arguments[0] == '-h' || arguments[0] == '--help')) {
      print('Usage: \ndart bin/main.dart \n${parser.usage}');
      exit(0);
    }
    var args = CommandLineParser().getParserResults(arguments, parser);
    var filePath = args['file_path'];
    // var challenge = args['from_response'];
    // var aesKeyFile = args['aes_key'];
    var privateKey;
    var formattedPrivateKey;
    if (filePath.endsWith(AT_KEYS)) {
      privateKey = await getSecretFromAtKeys(filePath);
    } else {
      print('Usage : \n${parser.usage}');
      exit(0);
    }
    if (privateKey != null) {
      privateKey = privateKey.trim();
      var key = crypton.RSAPrivateKey.fromString(privateKey);

      formattedPrivateKey = key.toFormattedPEM();
      final pem = correctKeyFormat(formattedPrivateKey);

      final pkcsParser = RSAPKCSParser();
      final pair = pkcsParser.parsePEM(pem);

      print("\nThese are the parameters \"n, e, d, p, q\", from which your private key can be restored. Do not share this information, as it could compromise your security.");
      print("Paste this on the \"settings.json\" file of your Raspberry Pi Pico W:\n");

      print("\"privateKey\": [\n\t\t\t${pair.private!.modulus}, " + 
        "\n\t\t\t${pair.private!.publicExponent}, " + 
        "\n\t\t\t${pair.private!.privateExponent}, " + 
        "\n\t\t\t${pair.private!.prime1}, " + 
        "\n\t\t\t${pair.private!.prime2}\n\t\t  ]");

      // challenge = challenge.trim();
      // var signature =
      //     base64.encode(key.createSHA256Signature(utf8.encode(challenge) as Uint8List));
      // stdout.write(signature);
      // stdout.write('\n');
    }

  } on ArgParserException catch (e) {
    print('$e');
  } on Exception catch (e) {
    print('Exception : $e');
  }
}

Future<String?> getSecretFromAtKeys(String filePath) async {
  try {
    var isFileExists = await File(filePath).exists();
    if (!isFileExists) {
      throw Exception('File not found');
    }
    var fileContents = File(filePath).readAsStringSync();
    var keysJSON = json.decode(fileContents);
    var encryptedPKAMPrivateKey = keysJSON['aesPkamPrivateKey'];
    var aesEncryptionKey = keysJSON['selfEncryptionKey'];
    var pkamPrivateKey =
        decryptValue(encryptedPKAMPrivateKey, aesEncryptionKey);
    // print("PkamPrivateKey in clear: $pkamPrivateKey");
    // print("\n\n\n------------------------------------------------------------------\n\n");
    return pkamPrivateKey;
  } on Exception catch (e) {
    print('Exception while getting secret : $e');
    return null;
  }
}

Future<String?> getSecretFromZip(String filePath, String aesKeyFilePath) async {
  try {
    var isFileExists = await File(filePath).exists();
    if (!isFileExists) {
      throw Exception('keys zip file not found');
    }
    late var fileContents;
    var bytes = File(filePath).readAsBytesSync();
    final archive = ZipDecoder().decodeBytes(bytes);
    for (var file in archive) {
      if (file.name.contains('atKeys')) {
        fileContents = String.fromCharCodes(file.content);
      }
    }
    var keysJSON = json.decode(fileContents);
    var encryptedPKAMPrivateKey = keysJSON['aesPkamPrivateKey'];
    var isAesFileExists = await File(aesKeyFilePath).exists();
    if (!isAesFileExists) {
      throw Exception(
          'aes key file path not provided \nUsage: \n${parser.usage}');
    }
    var aesKey = File(aesKeyFilePath).readAsStringSync();
    aesKey = aesKey.trim();
    var pkamPrivateKey = decryptValue(encryptedPKAMPrivateKey, aesKey);
    return pkamPrivateKey;
  } on Exception catch (e) {
    print('Exception while getting secret : $e');
    return null;
  }
}

String decryptValue(String encryptedValue, String decryptionKey) {
  var aesKey = AES(Key.fromBase64(decryptionKey));
  var decrypter = Encrypter(aesKey);
  var iv2 = IV.fromLength(16);
  return decrypter.decrypt64(encryptedValue, iv: iv2);
}

String correctKeyFormat(String formattedKey) {
  LineSplitter ls = LineSplitter();
  final lines = ls.convert(formattedKey);
  lines[0] = "-----BEGIN PRIVATE KEY-----";
  lines[lines.length - 1] = "-----END PRIVATE KEY-----";
  var result = "";
  for(int i = 0; i < lines.length; i++) {
    result += lines[i] + ((i != lines.length) ? "\n" : "");
  }
  return result;
}
