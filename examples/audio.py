#!/usr/bin/env python3
import requests
import argparse
import os

def generate_request(input_path, output_path): 
    # Open the file in binary mode
    with open(input_path, 'rb') as audio_file:
        # Define the files dictionary
        files = {'file': ("audio.mp3", audio_file, 'audio/mp3')}
                
        # Create the POST request
        request = requests.Request('POST', "http://localhost:8000", files=files)
        prepared = request.prepare()
        with open(output_path, "w") as f:
            f.write("POST /v1/audio/transcriptions HTTP/1.1\r\n")
            f.write("Host: localhost\r\n")
            for key, value in prepared.headers.items(): 
                f.write(key + ": " + value + "\r\n")
            f.write("\r\n")
        
        with open(output_path, "ab") as f:
            f.write(prepared.body)
        
def main():
    parser = argparse.ArgumentParser(description="Utility to generate HTTP requests containing an audio file")
    parser.add_argument('--input', type=str, help="Path to the input file.")
    parser.add_argument('--output', type=str, help="Path to the output file.")
    
    args = parser.parse_args()
    
    generate_request(args.input, args.output)
    
if __name__=="__main__":
    main()
