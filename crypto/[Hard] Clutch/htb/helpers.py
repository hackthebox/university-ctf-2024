USABLE_FRAMES = {
    ("1x,0z", "1x,1z"): "f2",
    ("0x,1z", "1x,1z"): "f3",
    ("1x,1z", "0x,1z"): "f4",
    ("1x,1z", "1x,0z"): "f6"
}

AUXILIARY_FRAMES = {
    ("0x,0z", "0x,0z"): "f7",
    ("0x,0z", "1x,1z"): "f8",
    ("0x,1z", "0x,0z"): "f9",
    ("1x,0z", "0x,0z"): "f10"
}

VALID_SS = {
    "f2": ["00,11", "01,01", "10,01", "11,11"],
    "f3": ["00,11", "01,01", "10,01", "11,11"],
    "f4": ["00,11", "01,10", "10,10", "11,11"],
    "f6": ["00,11", "01,10", "10,10", "11,11"]
}

ALICE_MR_DERIVATION = {
    "f2": {
        "00": "00",
        "01": "01",
        "10": "11",
        "11": "10"
    },
    "f3": {
        "00": "01",
        "01": "10",
        "10": "00",
        "11": "11"
    },
    "f4": {
        "00": "01",
        "01": "11",
        "10": "00",
        "11": "10"
    },
    "f6": {
        "00": "00",
        "01": "01",
        "10": "10",
        "11": "11"
    }
}

BOB_MR_DERIVATION = {
    ("X", "X"): "00",
    ("Z", "Z"): "01",
    ("X", "Z"): "10",
    ("Z", "X"): "11"
}

ERROR_CORRECTION_RULES = {
    "f2": [0, "f10", "01,10", ["01,01", "10,01"]],
    "f3": [0, "f9" , "10,10", ["10,01", "01,01"]],
    "f4": [1, "f9" , "10,10", ["10,10", "01,10"]],
    "f6": [1, "f10", "01,10", ["01,10", "10,10"]]
}

KEY_DERIVATION = {
    "00,11": {
        "00": "0",
        "01": "1"
    },
    "11,11": {
        "11": "0",
        "10": "1"
    },
    "01,10": {
        "01": "0",
        "11": "1"
    },
    "01,01": {
        "10": "0",
        "01": "1"
    },
    "10,01": {
        "00": "0",
        "11": "1"
    },
    "10,10": {
        "00": "0",
        "10": "1"
    }
}