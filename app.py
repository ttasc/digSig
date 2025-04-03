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
secret_key = os.getenv('SECRET_KEY')
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

        try:
            with open(temp_path, 'rb') as f:
                w = IncrementalPdfFileWriter(f, strict=False)

                # Tạo tên trường chữ ký duy nhất bằng UUID
                field_name = f"Signature_{uuid.uuid4().hex[:8]}"

                signers.PdfSigner(
                    signers.PdfSignatureMetadata(field_name=field_name),  # Sử dụng tên duy nhất
                    signer=signer,
                ).sign_pdf(
                    pdf_out=w,
                    output=open(signed_path, 'wb'),
                )

            # Dọn dẹp file tạm
            os.remove(temp_path)

            return send_file(signed_path, as_attachment=True, download_name='signed.pdf')

        except Exception as e:
            # Dọn dẹp file tạm nếu có lỗi
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(signed_path):
                os.remove(signed_path)
            return render_template('sign.html', signatures=signatures, error=f"Lỗi khi ký file: {str(e)}")

    return render_template('sign.html', signatures=signatures)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'email' not in session:
        return redirect(url_for('index'))

    email = session['email']
    message = None
    all_valid = True
    all_signatures = []
    modified_after_signing = False

    if request.method == 'POST':
        pdf_file = request.files['pdf_file']
        user_dir = get_user_dir(email)
        temp_path = os.path.join(user_dir, 'verify_temp.pdf')
        pdf_file.save(temp_path)

        try:
            with open(temp_path, 'rb') as f:
                reader = PdfFileReader(f, strict=False)
                if not reader.embedded_signatures:
                    message = "⚠️ Không tìm thấy chữ ký trong file PDF!"
                else:
                    for sig in reader.embedded_signatures:
                        status = validate_pdf_signature(sig)

                        signer_info = {
                            'name': 'Không rõ',
                            'email': 'Không rõ',
                            'organization': 'Không rõ'
                        }

                        try:
                            # Lấy chứng chỉ từ signature
                            if hasattr(sig, 'signer_cert'):
                                cert = sig.signer_cert
                                # Trích xuất thông tin từ chứng chỉ
                                for attr in cert.subject:
                                    if attr.oid == NameOID.EMAIL_ADDRESS:
                                        signer_info['email'] = attr.value
                                    elif attr.oid == NameOID.COMMON_NAME:
                                        signer_info['name'] = attr.value
                                    elif attr.oid == NameOID.ORGANIZATION_NAME:
                                        signer_info['organization'] = attr.value
                        except Exception as e:
                            print(f"Lỗi khi trích xuất chứng chỉ: {str(e)}")

                        # Lấy thời gian ký
                        signing_time = None
                        if sig.sig_object.get('/M'):
                            try:
                                signing_time = sig.sig_object['/M'].decode('utf-8')
                            except:
                                signing_time = str(sig.sig_object['/M'])

                        signature_data = {
                            'valid': status.valid,
                            'intact': status.intact,
                            'signer': signer_info['name'],
                            'email': signer_info['email'],
                            'organization': signer_info['organization'],
                            'signing_time': signing_time or 'Không rõ',
                            'details': status.pretty_print_details(),
                        }
                        all_signatures.append(signature_data)

                        if not status.valid:
                            all_valid = False
                        if not status.intact:
                            modified_after_signing = True

                    # Tạo thông báo tổng hợp
                    total_signatures = len(all_signatures)
                    valid_count = sum(1 for sig in all_signatures if sig['valid'])

                    if all_valid and not modified_after_signing:
                        message = f"✅ Tất cả {total_signatures} chữ ký đều hợp lệ và file không bị thay đổi!"
                    elif valid_count > 0:
                        message = f"⚠️ {valid_count}/{total_signatures} chữ ký hợp lệ"
                        if modified_after_signing:
                            message += " (file đã bị thay đổi sau khi ký)"
                    else:
                        message = "❌ Không có chữ ký nào hợp lệ!"

        except Exception as e:
            message = f"⛔ Lỗi: {str(e)}"
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return render_template('verify.html', message=message, all_valid=all_valid, all_signatures=all_signatures, modified=modified_after_signing)

@app.template_filter('parse_pdf_date')
def parse_pdf_date_filter(pdf_date_str):
    try:
        if pdf_date_str.startswith('D:'):
            date_str = pdf_date_str[2:16]  # Lấy phần YYYYMMDDHHmmSS
            return datetime.strptime(date_str, '%Y%m%d%H%M%S').strftime('%d/%m/%Y %H:%M:%S')
        return pdf_date_str
    except:
        return pdf_date_str

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=port, debug=True)
