import streamlit as st
import pandas as pd
import subprocess
import os
import time

def run_and_display_stdout(*cmd_with_args, cwd):
    result = subprocess.Popen(cmd_with_args, stdout=subprocess.PIPE, cwd=cwd)
    results = False
    for line in iter(lambda: result.stdout.readline(), b""):
        str = line.decode('utf-8') 
        if "cargo" in str: 
            continue
        if "localhost" in str: 
            continue
        if "--config" in str:
            continue
        if "--kms-cert" in str:
            continue
                    
        if "results" in str or results: 
            col1.write(str)
            continue
        yield str
        time.sleep(0.02)

def main():
    st.set_page_config (layout="wide")
    st.title('Confidential Inferencing with Whisper')

    audio_file = st.file_uploader("Upload audio", type=["mp3","wav"])

    global col1
    col1, col2 = st.columns(2)
    if audio_file is not None:
        with open(audio_file.name,"wb") as f:
            f.write((audio_file).getbuffer())
        os.environ['INPUT'] = audio_file.name
        col2.write_stream(run_and_display_stdout("make", "run-client-kms", cwd="."))

if __name__ == "__main__":
    main()
