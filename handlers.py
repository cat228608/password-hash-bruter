from flask import Flask, request, jsonify, Response
import hashlib
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/crack', methods=['POST'])
def crack_hash():
    data = request.get_json()
    hash_to_crack = data.get('hash')
    password_file_url = data.get('passwordFileUrl')
    algorithm = data.get('algorithm')

    if not all([hash_to_crack, password_file_url, algorithm]):
        return jsonify({'error': 'Missing parameters'}), 400

    try:
        response = requests.get(password_file_url, stream=True)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        lines_checked = 0

        def generate():
            nonlocal lines_checked
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                for line in chunk.decode('utf-8', errors='ignore').splitlines():
                    lines_checked += 1
                    password = line.strip()

                    if algorithm == 'md5':
                        hashed_password = hashlib.md5(password.encode()).hexdigest()
                    elif algorithm == 'sha1':
                        hashed_password = hashlib.sha1(password.encode()).hexdigest()
                    elif algorithm == 'sha256':
                        hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    elif algorithm == 'sha384':
                        hashed_password = hashlib.sha384(password.encode()).hexdigest()
                    elif algorithm == 'sha512':
                        hashed_password = hashlib.sha512(password.encode()).hexdigest()
                    else:
                        yield f'Ошибка: Неверный алгоритм\n'
                        return

                    if hashed_password == hash_to_crack:
                        yield f'Хэш найден: {password}\n'
                        return

                    if lines_checked % 100 == 0:
                        yield f'Проверено: {lines_checked}/{total_size}\n'

            # Обновляем прогресс бар до 100% после завершения проверки
            yield f'Проверено: {total_size}/{total_size}\n'
            yield f'Хэш не найден\n' 

        return Response(generate(), mimetype='text/plain')

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Ошибка при загрузке файла с паролями: {e}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
