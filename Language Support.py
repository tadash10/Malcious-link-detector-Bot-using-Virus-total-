translations = {
    'en': {
        'malicious': 'malicious',
        'safe': 'safe',
        'invalid_url': 'Please send a valid URL.',
        'phishing_tips': 'Be wary of unsolicited messages, check the sender’s address, and avoid clicking on unknown links.',
    },
    'es': {
        'malicious': 'malicioso',
        'safe': 'seguro',
        'invalid_url': 'Por favor, envía una URL válida.',
        'phishing_tips': 'Desconfía de mensajes no solicitados, verifica la dirección del remitente y evita hacer clic en enlaces desconocidos.',
    },
    'pt': {
        'malicious': 'malicioso',
        'safe': 'seguro',
        'invalid_url': 'Por favor, envie uma URL válida.',
        'phishing_tips': 'Desconfie de mensagens não solicitadas, verifique o endereço do remetente e evite clicar em links desconhecidos.',
    }
}

def get_translation(lang_code, key):
    return translations.get(lang_code, translations['en']).get(key, translations['en'][key])
