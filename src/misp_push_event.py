import os, glob, json
from pymisp import PyMISP
# get local misp credential
from conf.misp_conf import misp_url, misp_user_key, misp_verifycert

def load_json_files():
    #Prend tous les fichiers dans le dossier feeds
    json_files = glob.glob("./feeds/**/*.json")
    events = []
    #Pour chaque fichier les importes dans le MISP local
    for json_file in json_files:
        if (json_file != "manifest.json"):
            with open(json_file, 'r') as f:
                event = json.load(f)
            try:
                misp.add_event(event)
                print(f'Successfully imported to misp {json_file}')
            except Exception as e:
                print(f'Error importing {json_file}: {e}')
    return events

if __name__ == '__main__':
    misp = PyMISP(misp_url, misp_user_key, misp_verifycert, 'json')
    events = load_json_files()