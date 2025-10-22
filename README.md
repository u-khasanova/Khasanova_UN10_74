# File format detection using YARA

## Analyze File Formats

### Analyze Signatures of ZIP Format

```hex
50 4B 01 02 or 50 4B 07 08 - ZIP format signature
```

### Analyze Signatures of RAR Format

```hex
52 61 72 21 1A 07 01 00 - RAR Signature
```

### Analyze Signatures of JPEG Format
```hex
FF D8 FF - JPEG Signature
```

### Analyze Signatures of MP3 Format
```hex
49 44 33 - MP3 Signature or
FF F2 or FF F3
```

## Make YARA Rule

```yara
rule FileExtensionDetector {
	meta: 
		description = "Обнаружение файлов форматов RAR, ZIP, MP3, JPEG"
		author = "Хасанова У.Н."
		
	strings: 
		$rar = { 52 61 72 21 1A 07 01 00 }
		$zip = { 50 4B ( 01 02 | 07 08 )}
		$jpeg = { FF D8 FF }
		$mp3 = { ( 49 44 33 | FF ( F2 | F3 ) ) }
	
	condition: 
		$rar or $zip or $jpeg or $mp3  
}
```

## Testing and Validation

### Create test directory structure:
```powershell
call > test.zip.fake
call > test.rar.fake
call > test.mp3.fake
call > test.jpg.fake
call > test.jpeg.fake
```

### Run YARA scan:
```powershell
& "C:\Program Files\YARA\yara64.exe" -r .\FileFormatDetector.yar .\test_files\
```

## Takeaway

Ключевые команды для работы: `yara -r правила.яр директория` и `fhx файл` для анализа hex-дампов.
