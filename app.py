import os
from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

TEMP_FOLDER = '.tmp'
os.makedirs(TEMP_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = TEMP_FOLDER
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-keys', methods=['GET', 'POST'])
def generate_keys():
    if request.method == 'POST':
        # Tạo cặp khóa RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Lưu private key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Lưu public key
        pem_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Lưu vào file tạm
        private_path = os.path.join(app.config['UPLOAD_FOLDER'], 'private_key.pem')
        public_path = os.path.join(app.config['UPLOAD_FOLDER'], 'public_key.pem')

        with open(private_path, 'wb') as f:
            f.write(pem_private)

        with open(public_path, 'wb') as f:
            f.write(pem_public)

        return render_template('generate_keys.html',
                             private_key=private_path,
                             public_key=public_path)

    return render_template('generate_keys.html')

@app.route('/sign', methods=['GET', 'POST'])
def sign():
    if request.method == 'POST':
        # Xử lý file upload
        pdf_file = request.files['pdf']
        private_key_file = request.files['private_key']

        # Lưu file tạm
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], str(pdf_file.filename))
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], str(private_key_file.filename))

        pdf_file.save(pdf_path)
        private_key_file.save(key_path)

        # Đọc private key
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        # Tạo chữ ký
        with open(pdf_path, 'rb') as f:
            pdf_data = f.read()

        signature = private_key.sign(
            pdf_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Lưu chữ ký
        sig_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signature.sig')
        with open(sig_path, 'wb') as f:
            f.write(signature)

        return render_template('sign.html', signature=sig_path)

    return render_template('sign.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    result = None
    if request.method == 'POST':
        # Xử lý file upload
        pdf_file = request.files['pdf']
        public_key_file = request.files['public_key']
        signature_file = request.files['signature']

        # Lưu file tạm
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], str(pdf_file.filename))
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], str(public_key_file.filename))
        sig_path = os.path.join(app.config['UPLOAD_FOLDER'], str(signature_file.filename))

        pdf_file.save(pdf_path)
        public_key_file.save(key_path)
        signature_file.save(sig_path)

        # Đọc public key
        with open(key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

        # Đọc chữ ký
        with open(sig_path, 'rb') as f:
            signature = f.read()

        # Xác minh
        with open(pdf_path, 'rb') as f:
            pdf_data = f.read()

        try:
            public_key.verify(
                signature,
                pdf_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            result = {
                'status': 'success',
                'message': 'Chữ ký hợp lệ! File không bị thay đổi.'
            }
        except Exception as e:
            result = {
                'status': 'danger',
                'message': f'Chữ ký không hợp lệ!'
            }

        return render_template('verify.html', result=result)

    return render_template('verify.html')

@app.route('/download/<path:filename>')
def download(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
