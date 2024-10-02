import streamlit as st
import pandas as pd
import jwt
import subprocess
import os
import time
import json
import requests

import urllib3
urllib3.disable_warnings()

def run_and_display_stdout(*cmd_with_args, cwd):
    result = subprocess.Popen(cmd_with_args, stdout=subprocess.PIPE, cwd=cwd)
    results = False
    for line in iter(lambda: result.stdout.readline(), b""):
        str = line.decode('utf-8') 
        print(str.strip())
        if str.startswith("Loaded"):
            print("   (press key to continue to step 2)")
            time.sleep(10)

        if "\"text\"" in str or results:
            out = json.loads(str)
            yield out["text"]
        time.sleep(0.02)

def attest(col):
    response = requests.get('https://confwhispertest.openai.azure.com:9443/discover', verify=False)
    claims = jwt.decode(response.content, options={"verify_signature": False})
    df = []
    for claim, value in claims.items():
        if claim == "x-ms-isolation-tee" or claim == "x-ms-runtime":
            for k,v in value.items():
                df.append({"claim": claim+"."+k, "value": str(v)})
        else:
            df.append({"claim":claim, "value": str(value)})

    with col:
        st.dataframe(pd.DataFrame(df), height=500, use_container_width=True)

def main():
    st.set_page_config (layout="wide")
    st.title('Sample Confidential Whisper Application')

    audio_file = st.file_uploader("Upload audio", type=["mp3","wav"])

    global col1
    col1, col2 = st.columns(2)
    if audio_file is not None:
        with open(audio_file.name,"wb") as f:
            f.write((audio_file).getbuffer())
        os.environ['INPUT'] = audio_file.name
        
        with col1:
            st.header("Attestation information")
        with col2:
            st.header("Transcription result")
            col2.write_stream(run_and_display_stdout("target/debug/ohttp-client", "--kms-cert","examples/kms.pem","-i",audio_file.name, "https://confwhispertest.openai.azure.com:9443/score", cwd="."))
        
        attest(col1)

if __name__ == "__main__":
    main()
