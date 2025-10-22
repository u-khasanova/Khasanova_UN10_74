# Обнаружение форматов файлов с помощью YARA

Проект демонстрирует использование YARA для обнаружения файлов различных форматов (ZIP, RAR, JPEG, MP3) на основе их сигнатур.

## Технические детали

- **Используемая версия YARA**: 4.5.4
- **ОС**: Windows 11 Pro

## Анализ форматов файлов

### Анализ сигнатур ZIP формата
![ZIP сигнатуры](/images/1.jpg)

```hex
50 4B 01 02 или 50 4B 07 08 (источник: wikipedia) - сигнатура ZIP формата
```

### Анализ сигнатур RAR формата
![RAR сигнатуры](/images/2.jpg)
```hex
52 61 72 21 1A 07 01 00 - сигнатура RAR
```

### Анализ сигнатур JPEG формата
![JPEG сигнатуры](/images/3.jpg)
```hex
FF D8 FF - сигнатура JPEG
```

### Анализ сигнатур MP3 формата
![MP3 сигнатуры](/images/4.jpg)
```hex
49 44 33 - сигнатура MP3 или
FF F2 или FF F3 (источник: wikipedia)
```

## Создание YARA правила

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
![YARA rule](FileExtensionDetector.yar)

## Тестирование и валидация

### Создание тестовой структуры директорий и fake-файлов:
```powershell
mkdir test-files
call > test.zip.fake
call > test.rar.fake
call > test.mp3.fake
call > test.jpg.fake
call > test.jpeg.fake
mv *zip ./test-files
mv *rar ./test-files
mv *jpg ./test-files
mv *mp3 ./test-files
mv *.fake ./test-files
```

### Запуск YARA сканирования:
```powershell
& "C:\Program Files\YARA\yara64.exe" -r .\FileFormatDetector.yar .\test_files\
```

![Запуск YARA](/images/5.jpg)

## Выводы

Сигнатуры файлов обеспечивают надежную идентификацию независимо от расширений файлов. Все файлы, которые предполагалось обнаружить, были успешно выявлены с помощью анализа сигнатур.
Подход применим для широкого спектра файловых форматов.
