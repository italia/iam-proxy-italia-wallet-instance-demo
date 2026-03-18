#!/bin/sh

echo "ENTRYPOINT WI"

echo "CREATION ENVIRONMENT"
python -m venv venv

echo "ACTIVATION ENVIRONMENT"
source venv/bin/activate

echo "INSTALL ALL DEPENDENCY"
pip install .

echo "RUN APPLICATION"
python app.py