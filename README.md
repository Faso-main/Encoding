# Image Text Encoder/Decoder

A simple Python script that encodes text into a black-and-white image and decodes it back using PIL and NumPy.

## Features
- Encodes text into a noise-covered image
- Stores message length in first 32 pixels
- Decodes hidden messages from images

## Usage
1. Run script: `python Main.py`
2. Enter text to encode (saves as `itr1.png`)
3. To decode: `decode_message_from_image('itr1.png')`

## Requirements
- Python 3
- Pillow (`pip install Pillow`)
- NumPy (`pip install numpy`)
