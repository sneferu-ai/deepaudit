#!/usr/bin/env python3
from __future__ import annotations
import pickle


def load_data(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    return pickle.loads(data)
