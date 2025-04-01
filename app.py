import os
import json
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature

load_dotenv()
secret_key = os.getenv('FLASK_SECRET_KEY')
port = int(os.getenv('PORT') or 5000)

app = Flask(__name__)
app.secret_key = secret_key

# Cấu hình thư mục
USERS_DIR = 'users'
os.makedirs(USERS_DIR, exist_ok=True)

# ==============================================
# Hàm hỗ trợ
# ==============================================
def get_user_dir(email):
    safe_email = email.replace('@', '_').replace('.', '_')
    user_dir = os.path.join(USERS_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def load_signatures(email):
    user_dir = get_user_dir(email)
    sig_file = os.path.join(user_dir, 'signatures.json')
    if os.path.exists(sig_file):
        with open(sig_file, 'r') as f:
            return json.load(f)
    return []

def save_signatures(email, signatures):
    user_dir = get_user_dir(email)
    sig_file = os.path.join(user_dir, 'signatures.json')
    with open(sig_file, 'w') as f:
        json.dump(signatures, f)

def generate_self_signed_cert(private_key, email):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Personal Signer"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    return cert

# ==============================================
# Routes
# ==============================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    session['email'] = email
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('index'))
    email = session['email']
    signatures = load_signatures(email)
    return render_template('dashboard.html', email=email, signatures=signatures)

@app.route('/create_key')
def create_key():
    if 'email' not in session:
        return redirect(url_for('index'))

    email = session['email']
    user_dir = get_user_dir(email)

    # Tạo key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = str(uuid.uuid4())

    # Tạo chứng thư tự ký
    cert = generate_self_signed_cert(private_key, email)

    # Lưu private key và cert
    private_key_path = os.path.join(user_dir, f'{key_id}_private.pem')
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    cert_path = os.path.join(user_dir, f'{key_id}_cert.pem')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Cập nhật danh sách
    signatures = load_signatures(email)
    signatures.append({
        'id': key_id,
        'name': f'Signature {len(signatures)+1}',
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M")
    })
    save_signatures(email, signatures)

    return redirect(url_for('dashboard'))

@app.route('/delete_key/<key_id>')
def delete_key(key_id):
    if 'email' not in session:
        return redirect(url_for('index'))

    email = session['email']
    user_dir = get_user_dir(email)

    # Xóa file key và cert
    private_key_path = os.path.join(user_dir, f'{key_id}_private.pem')
    cert_path = os.path.join(user_dir, f'{key_id}_cert.pem')
    if os.path.exists(private_key_path):
        os.remove(private_key_path)
    if os.path.exists(cert_path):
        os.remove(cert_path)

    # Cập nhật danh sách
    signatures = load_signatures(email)
    signatures = [sig for sig in signatures if sig['id'] != key_id]
    save_signatures(email, signatures)

    return redirect(url_for('dashboard'))

@app.route('/sign', methods=['GET', 'POST'])
def sign_pdf():
    if 'email' not in session:
        return redirect(url_for('index'))

    email = session['email']
    user_dir = get_user_dir(email)
    signatures = load_signatures(email)

    if request.method == 'POST':
        key_id = request.form['key_id']
        pdf_file = request.files['pdf_file']

        # Đường dẫn file
        temp_path = os.path.join(user_dir, 'temp.pdf')
        signed_path = os.path.join(user_dir, 'signed.pdf')
        pdf_file.save(temp_path)

        # Load key và cert
        private_key_path = os.path.join(user_dir, f'{key_id}_private.pem')
        cert_path = os.path.join(user_dir, f'{key_id}_cert.pem')

        signer = signers.SimpleSigner.load(
            private_key_path,
            cert_path
        )

        with open(temp_path, 'rb') as f:
            w = IncrementalPdfFileWriter(f, strict=False)
            signers.PdfSigner(
                signers.PdfSignatureMetadata(field_name='Signature'),
                signer=signer,
            ).sign_pdf(
                pdf_out=w,
                output=open(signed_path, 'wb'),
            )

        # Dọn dẹp file tạm
        os.remove(temp_path)

        return send_file(signed_path, as_attachment=True, download_name='signed.pdf')

    return render_template('sign.html', signatures=signatures)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'email' not in session:
        return redirect(url_for('index'))

    email = session['email']
    message = None
    valid = False
    details = {}

    if request.method == 'POST':
        pdf_file = request.files['pdf_file']
        user_dir = get_user_dir(email)
        temp_path = os.path.join(user_dir, 'verify_temp.pdf')
        pdf_file.save(temp_path)

        try:
            with open(temp_path, 'rb') as f:
                reader = PdfFileReader(f)
                if not reader.embedded_signatures:
                    message = "⚠️ Không tìm thấy chữ ký trong file PDF!"
                else:
                    sig = reader.embedded_signatures[0]
                    status = validate_pdf_signature(sig)
                    valid = status.valid
                    details = {
                        'details': status.pretty_print_details(),
                    }
                    # details = {
                    #     'signer': status.signer_name,
                    #     'signing_time': status.signing_time.strftime("%Y-%m-%d %H:%M:%S") if status.signing_time else "Không xác định",
                    #     'hash_algo': status.signer_hash_algo
                    # }
                    message = "✅ Chữ ký hợp lệ!" if valid else "❌ Chữ ký không hợp lệ!"
        except Exception as e:
            message = f"⛔ Lỗi: {str(e)}"
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return render_template('verify.html', message=message, valid=valid, details=details)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=port, debug=True)
