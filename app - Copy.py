from typing import List
from flask import Flask, render_template, request, redirect, url_for, request, session, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import sqlalchemy
import bcrypt
import os
import uuid
import datetime
from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy import ForeignKey
from flask import send_from_directory
from flask import make_response
from werkzeug.utils import secure_filename
import json

from io import BytesIO
#from reportlab.pdfgen import canvas
import pdfkit

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost:3306/aim'
app.secret_key = 'Papua123'
app.config['UPLOAD_DIRECTORY'] = '/storage'


if not os.path.exists(app.config['UPLOAD_DIRECTORY']):
    os.mkdir(app.config['UPLOAD_DIRECTORY'])


db: sqlalchemy = SQLAlchemy(app)
migrate = Migrate(app, db)

################################################################

class User(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)

    email: str = db.Column(db.VARCHAR(255), unique=True, nullable=False)
    hashed_password: bytes = db.Column(db.BINARY(60), nullable=False)
    salt: bytes = db.Column(db.BINARY(60), nullable=False)

    role_id: int = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role: Mapped['Role'] = relationship('Role')

    person: Mapped['Person'] = relationship('Person', back_populates='user', cascade="all, delete")
    files: Mapped[List['File']] = relationship('File', back_populates='user', cascade="all, delete")

    @property
    def password(self) -> bytes:
        return self.hashed_password

    @password.setter
    def password(self, new_password: str):
        self.salt = bcrypt.gensalt()

        self.hashed_password = bcrypt.hashpw(bytes(new_password, 'utf-8'), self.salt)
    
    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(bytes(password, 'utf-8'), self.hashed_password)
################################################################

role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.ForeignKey('permission.id'), primary_key=True)
)

class Role(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.VARCHAR(10), nullable=False, unique=True)

    permissions: Mapped[List["Permission"]] = relationship('Permission', secondary=role_permissions)

class Permission(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.VARCHAR(20), nullable=False, unique=True)
    

################################################################

class Person(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    
    user_id: int = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    user: Mapped['User'] = relationship('User', back_populates='person')

    first_name: str = db.Column(db.VARCHAR(60), nullable=False)
    last_name: str = db.Column(db.VARCHAR(60))

    student: Mapped['Student'] = relationship('Student', back_populates='person', cascade="all, delete")
    staff: Mapped['Staff'] = relationship('Staff', back_populates='person', cascade="all, delete")
    author: Mapped['Author'] = relationship('Author', back_populates='person', cascade='all, delete')

class Student(db.Model):
    person_id: int = db.Column(db.Integer, db.ForeignKey('person.id'), primary_key=True)
    person: Mapped['Person'] = relationship('Person', back_populates='student')

    nim: str = db.Column(db.VARCHAR(15), unique=True, nullable=False)

class Staff(db.Model):
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), primary_key=True)
    person: Mapped['Person'] = relationship('Person', back_populates='staff')

    nip = db.Column(db.Integer, unique=True, nullable=False)
    
class Author(db.Model):
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), primary_key=True)
    person: Mapped['Person'] = relationship('Person', cascade='all, delete')

    collections: Mapped[List['Catalog']] = relationship('Catalog', secondary='catalog_authors', back_populates='authors')

################################################################


class Publisher(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.VARCHAR(255), nullable=False)
    country_code: str = db.Column(db.VARCHAR(2)) # ISO 3166-1-alpha-2 (https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)

    catalogs: Mapped[List['Catalog']] = relationship('Catalog', back_populates='publisher')


class Subject(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.VARCHAR(255), unique=True, nullable=False)

    catalogs: Mapped[List['Catalog']] = relationship('Catalog', back_populates='subject')

catalog_authors = db.Table(
    'catalog_authors',
    db.Column('catalog_id', db.ForeignKey('catalog.id'), primary_key=True),
    db.Column('author_id', db.ForeignKey('author.person_id'), primary_key=True)
)

class Catalog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    title = db.Column(db.VARCHAR(255), nullable=False)
    language_code: str = db.Column(db.VARCHAR(3)) # ISO 639‑2 (https://www.loc.gov/standards/iso639-2/php/code_list.php)
    is_opac: bool = db.Column(db.Boolean, default=True)
    cover_url: str = db.Column(db.VARCHAR(500)) 

    authors: Mapped[List['Author']] = relationship('Author', secondary='catalog_authors', back_populates='collections')

    subject_no: int = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    subject: Mapped[List['Subject']] = relationship('Subject', back_populates='catalogs')
    
    publisher_id: int = db.Column(db.Integer, db.ForeignKey('publisher.id'), nullable=False)
    publisher: Mapped['Publisher'] = relationship('Publisher', back_populates="catalogs")
    publish_year: int = db.Column(db.Integer)
    publish_city = db.Column(db.VARCHAR(5)) # https://en.wikipedia.org/wiki/UN/LOCODE https://unece.org/trade/cefact/UNLOCODE-Download
    
    isbn: str = db.Column(db.VARCHAR(13), unique=True)
    call_no: str = db.Column(db.VARCHAR(255), unique=True)

    collections: Mapped[List['Collection']] = relationship('Collection', back_populates="catalog", cascade="all, delete")
    file_id: int = db.Column(db.Integer, db.ForeignKey('file.id'))
    file: Mapped['File'] = relationship('File')
    description = db.Column(db.VARCHAR(700))
    status: bool = db.Column(db.Boolean, default=False)
    abstract: str = db.Column(db.VARCHAR(700))
    date_acc = db.Column(db.Date)
    number_verif = db.Column(db.String(50))
    reject_status = db.Column(db.Boolean, default=False)
    checked_items = db.Column(db.JSON, default={})


class Collection(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    
    barcode_no: str = db.Column(db.VARCHAR(50), unique=True, nullable=False)
    registration_no: str = db.Column(db.VARCHAR(50), unique=True, nullable=False)
    call_no: str = db.Column(db.VARCHAR(255), unique=True, nullable=False)
    is_opac: bool = db.Column(db.Boolean, default=True)
    
    catalog_id = db.Column(db.Integer, db.ForeignKey('catalog.id'), nullable=False)
    catalog: Mapped['Catalog'] = relationship('Catalog', back_populates='collections')



class FileType(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)

    name: str = db.Column(db.VARCHAR(50), unique=True)



import os

class File(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    
    _filename: str = db.Column(db.VARCHAR(255), unique=True)

    user_id: int = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='files')

    file_type_id = db.Column(db.Integer, db.ForeignKey('file_type.id'), nullable=False)
    file_type = relationship('FileType')

    def __init__(self, file, file_type):
        super().__init__()
        self.file = file
        self.file_type = file_type

    @property
    def file_path(self):
        return os.path.join(app.config['UPLOAD_DIRECTORY'], self._filename)

    @property
    def file(self):
        return send_from_directory(app.config['UPLOAD_DIRECTORY'], self._filename)
    
    @file.setter
    def file(self, file):
        extension = file.filename.rsplit('.', 1)[1].lower()
        filename = uuid.uuid4().hex + '.' + extension
        file.save(os.path.join(app.config['UPLOAD_DIRECTORY'], filename))
        self._filename = filename 

    def delete_file(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        db.session.delete(self)
        db.session.commit()

    # Contoh penggunaan di view:
    # from flask import send_from_directory
    # @app.route('/uploads/<name>')
    # def download_file(name):
    #    file = Document.query.filter_by(id=1).first()
    #    return send_from_directory(document.file)

    @property
    def file(self):
        return send_from_directory(app.config['UPLOAD_DIRECTORY'], self._filename)
    
    @file.setter
    def file(self, file):
        # File berasal dari form atau request
        extension = file.filename.rsplit('.', 1)[1].lower()
        filename = uuid.uuid4().hex + '.' + extension

        file.save(os.path.join(app.config['UPLOAD_DIRECTORY'], filename))
        self._filename = filename 

    def delete(self):
        os.remove(self.file)
        self.delete()

class StatusCatalog(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    status: bool = db.Column(db.Boolean, default=False)
    catalog_id = db.Column(db.Integer, db.ForeignKey('catalog.id'), nullable=False)
    catalog: Mapped['Catalog'] = relationship('Catalog')

########################################################################################################


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


@app.route("/")
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        nim = request.form['nim']
        first_name = request.form['first_name']
        last_name = request.form['last_name']

        # Cari atau buat peran "member" jika belum ada
        role = Role.query.filter_by(name='member').first()
        if not role:
            role = Role(name='member')
            db.session.add(role)
            db.session.commit()

        # Hash password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        new_user = User(
            email=email,
            hashed_password=hashed_password,
            salt=salt,
            role=role
        )

        # Buat objek Person dan hubungkan dengan objek User
        person = Person(first_name=first_name, last_name=last_name, user=new_user)

        # Buat objek Student dan hubungkan dengan objek Person
        student = Student(nim=nim, person=person)

        db.session.add(new_user)
        db.session.commit()

        flash('Pendaftaran berhasil!')
        return redirect(url_for('login'))  # Redirect ke halaman login setelah pendaftaran

    return render_template('register.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):  # Tidak perlu melakukan encode('utf-8') di sini
            session['user_id'] = user.id
            flash('Login berhasil!')
            return redirect(url_for('dashboard'))
        else:
            flash('Login gagal. Periksa kembali email dan password Anda.')
    return render_template('login.html')


@app.before_request
def before_request():
    # Periksa apakah pengguna sudah login
    if 'user_id' in session:
        # Jika pengguna sudah login dan mencoba mengakses halaman login, arahkan ke halaman dashboard
        if request.endpoint == 'login':
            return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Anda telah logout.')
    return redirect(url_for('index'))  


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.role_id == 1:
                # Jika role id adalah 1 (admin), arahkan ke halaman dashboard admin
                students = Student.query.all()
                return render_template('dashboard_admin.html', students=students)
            elif user.role_id == 2:
                person = Person.query.filter_by(user_id=user.id).first()
                author = Author.query.filter_by(person_id=person.id).first()
                student = Student.query.filter_by(person_id=person.id).first()
                status_catalog = None
                
                print(person.first_name + ' ' + person.last_name)
                name= person.first_name + ' ' + person.last_name
                if author:
                    catalog = author.collections[0]
                    #print(author.collections[0])
                    status_catalog = catalog.status
                    #status_catalog = StatusCatalog.query.filter_by(catalog_id=author.collections[0].id).first()
                    print(status_catalog)
                return render_template('dashboard_student.html', status_catalog=status_catalog, name=name)
            else:
                flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
                return redirect(url_for('login'))
        else:
            flash('Pengguna tidak ditemukan.')
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/edit_student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 1:
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('dashboard'))

    student = Student.query.get_or_404(student_id)
    catalog = None

    if student.person.author and student.person.author.collections:
        catalog = student.person.author.collections[0]

    if request.method == 'POST':
        student.person.first_name = request.form.get('first_name', '')
        student.person.last_name = request.form.get('last_name', '')

        if catalog:
            # Handle status safely
            new_status = int(request.form.get('status', '0'))
            
            if new_status == 1:  # If status is changed to Active
                catalog.status = 1
                catalog.reject_status = False  # Set reject_status to False (0)
                catalog.checked_items = {}  # Empty the checked_items
                catalog.description = ''
            else:
                catalog.status = 0
                
                # Handle reject status
                new_reject_status = request.form.get('reject_status', '0') == '1'
                
                # Jika status berubah menjadi reject, hapus file
                # if new_reject_status and not catalog.reject_status:
                #     if catalog.file:
                #         catalog.file.delete_file()
                #         catalog.file = None

                catalog.reject_status = new_reject_status

                # Handle checked items only if status is not Active
                checked_items_json = request.form.get('checked_items', '{}')
                try:
                    checked_items = json.loads(checked_items_json)
                    if isinstance(checked_items, dict):
                        catalog.checked_items = checked_items
                    else:
                        # Jika bukan dict, mungkin kita menerima list
                        catalog.checked_items = {item: True for item in checked_items if item}
                except json.JSONDecodeError:
                    print('Invalid JSON:', checked_items_json)
                    catalog.checked_items = {}

            # Handle description
            if new_status != 1:
                catalog.description = request.form.get('description', '')

        try:
            db.session.commit()
            flash('Data mahasiswa berhasil diperbarui.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')
        
        return redirect(url_for('dashboard'))

    return render_template('edit_student.html', student=student, catalog=catalog)
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 1:
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('dashboard'))

    student = Student.query.get_or_404(student_id)
    catalog = None

    if student.person.author and student.person.author.collections:
        catalog = student.person.author.collections[0]

    if request.method == 'POST':
        student.person.first_name = request.form.get('first_name', '')
        student.person.last_name = request.form.get('last_name', '')

        if catalog:
            # Inisialisasi checked_items jika None
            if catalog.checked_items is None:
                catalog.checked_items = {}

            # Handle status safely
            catalog_status = request.form.get('status')
            if catalog_status is not None:
                catalog.status = int(catalog_status)
            
            # Handle description
            catalog.description = request.form.get('description', '')
            
            # Handle reject status
            new_reject_status = request.form.get('reject_status', '0') == '1'

            if new_reject_status and not catalog.reject_status:
                if catalog.file:
                    catalog.file.delete_file()
                    catalog.file = None
            catalog.reject_status = new_reject_status            
            # Handle checked items
            checked_items_json = request.form.get('checked_items', '{}')
            try:
                checked_items = json.loads(checked_items_json)
                if isinstance(checked_items, dict):
                    catalog.checked_items = checked_items
                else:
                    # Jika bukan dict, mungkin kita menerima list
                    catalog.checked_items = {item: True for item in checked_items if item}
            except json.JSONDecodeError:
                
                print('Invalid JSON:', checked_items_json)
                catalog.checked_items = {}

        try:
            db.session.commit()
            flash('Data mahasiswa berhasil diperbarui.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')
        
        return redirect(url_for('dashboard'))

    return render_template('edit_student.html', student=student, catalog=catalog)

@app.route('/formulir_collection', methods=['GET', 'POST'])
def formulir_collection():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role_id == 2:  # Check if the user is a student
            person = Person.query.filter_by(user_id=user.id).first()
            student = Student.query.filter_by(person_id=person.id).first()
            author = Author.query.filter_by(person_id=person.id).first()
            # Mendapatkan data dari Person dan Student
            nama_default = f"{person.first_name} {person.last_name if person.last_name else ''}"
            nim_default = student.nim if student else ''

            first_name = person.first_name
            last_name = person.last_name
            print("Nilai nama_default:", nama_default)
            print("Nilai nim_default:", nim_default)
            status_catalog = None
            catalog_title = None
            subject_name = None
            abstract = None
            reject_status = False

            #status_catalog = StatusCatalog.query.filter_by(catalog_id=author.collections[0].id).first()
            #print(status_catalog)
            if author:
                catalog = author.collections[0]
                catalog_title = catalog.title
                subject_id = catalog.subject_no
                subject = Subject.query.get(subject_id)
                subject_name = subject.name
                status_catalog = 0
                abstract = catalog.abstract
                reject_status = catalog.reject_status
                print(catalog_title)
                print("status : ",status_catalog)
                print("reject status = ", reject_status)
            
            # print("setelah di isi " + abstract)

            if request.method == 'POST':
            
                # Mengambil data dari formulir
                nama = request.form['nama']
                nim = request.form['nim']
                judul_penelitian = request.form['judul_penelitian']
                prodi = request.form['prodi']
                departemen = request.form['departemen']
                abstract = request.form['abstract']

                # Mengambil file PDF yang diunggah
                pdf_file = request.files['pdf_file']

                if pdf_file:
                    #filename = pdf_file.filename
                    # pdf_file.save(f"{app.config['UPLOAD_DIRECTORY']}/{filename}")
                    
                    # Membuat objek FileType 'Skripsi'
                    file_type = FileType.query.filter_by(name='Skripsi').first()

                    # Membuat objek File
                    file_obj = File(pdf_file, file_type)
                    #file_obj._filename = filename

                    # Menyimpan objek File ke dalam database
                    # db.session.add(file_obj)
                    # db.session.commit()
                    
                    # Mengambil subjek dari form prodi
                    subject_name = prodi  # Sesuaikan dengan nilai yang sesuai dengan kebutuhan Anda

                    # Mengambil objek Subject berdasarkan nama
                    subject = Subject.query.filter_by(name=subject_name).first()
                    
                    today = datetime.datetime.now()
                    now_year = today.year

                    # Membuat objek Person jika belum ada
                    if not person:
                        person = Person(first_name=first_name, last_name=last_name, user=user)

                    # membuat oject file baru
                    new_file_obj = File(pdf_file, file_type)
                    #membuat author
                    if not author:
                        author = Author(person=person)
                    
                    universitas_hasanuddin_publisher = Publisher.query.get(1)
                    
                    db.session.add(author)
                    db.session.commit()

                    # Membuat objek Catalog
                    if catalog:
                        catalog.title = judul_penelitian
                        catalog.isbn = nim
                        catalog.abstract = abstract
                        catalog.subject = subject
                        catalog.publish_year = now_year
                        if catalog.file:
                            old_file = catalog.file
                            catalog.file = new_file_obj
                            db.session.delete(old_file)
                        else:
                            catalog.file = new_file_obj
                        catalog.reject_status = False  # Reset reject status
                        catalog.status = 0  # Reset status to pending
                    else:
                        catalog = Catalog(
                            title=judul_penelitian,
                            isbn=nim,
                            abstract=abstract,
                            language_code='ind',
                            is_opac=True,
                            authors=[author],  # Perlu diisi dengan daftar penulis (Author) sesuai kebutuhan
                            subject=subject,  # Perlu diisi dengan objek Subject sesuai kebutuhan
                            publisher=universitas_hasanuddin_publisher,  # Perlu diisi dengan objek Publisher sesuai kebutuhan
                            publish_year= now_year,  # Perlu diisi dengan tahun penerbitan sesuai kebutuhan
                            file=file_obj
                        )

                    # Menyimpan objek Catalog ke dalam database
                    # db.session.add(catalog)
                    # db.session.commit()

                    if prodi == "S1-Ilmu Hukum":
                        print("prodi s1 aman")
                    else:
                        print("gagal")
                    # Membuat objek Collection
                    if not catalog.collections:
                        collection = Collection(
                            barcode_no=nim,  # Sesuaikan dengan data yang sesuai kebutuhan
                            registration_no=nim,  # Sesuaikan dengan data yang sesuai kebutuhan
                            call_no=nim,  # Sesuaikan dengan data yang sesuai kebutuhan
                            is_opac=True,
                            catalog=catalog
                        )
                    
                        # Menyimpan objek Collection ke dalam database
                        db.session.add(collection)
                        db.session.commit()
                    
                    print("reject status = ", reject_status)
                # Mengembalikan respons sukses atau melakukan pengalihan ke halaman lain
                return render_template('dashboard_student.html')
            # print("luat  " + abstract) 
    return render_template('formulir_collection.html', nama_default=nama_default, nim_default=nim_default, status_catalog=status_catalog, catalog_title=catalog_title, subject_name=subject_name, abstract=abstract, reject_status=reject_status)



@app.route('/student_files/<int:student_id>')
def student_files(student_id):
    student = Student.query.get(student_id)
    
    person = Person.query.get(student.person_id)
    
    user = User.query.get(person.user_id)
    
    author = Author.query.filter_by(person_id=person.id).first()
    
    b = Catalog.query.join(Author, Catalog.authors).filter(Author.person_id == person.id).first()

    if b and b.file and b.file.file:
        print(f"File path: {b.file.file_path}")
        return b.file.file
    else:
        return "File belum tersedia", 404

@app.route('/file')
def tes():
    if 'user_id' in session:
        user: User = User.query.get(session['user_id'])
        if user and user.role_id == 2:
            person = Person.query.filter_by(user_id=user.id).first()
            student = Student.query.filter_by(person_id=person.id).first()
            author = Author.query.filter_by(person_id=person.id).first()
            b = Catalog.query.join(Author, Catalog.authors).filter(Author.person_id == user.person.id).first()
        return b.file.file
    else:
        return redirect(url_for('login'))

@app.route('/download')
def download():
    if 'user_id' in session:
        user: User = User.query.get(session['user_id'])
        if user and user.role_id == 2:
            person = Person.query.filter_by(user_id=user.id).first()
            student = Student.query.filter_by(person_id=person.id).first()
            author = Author.query.filter_by(person_id=person.id).first()


            first_name = person.first_name
            last_name = person.last_name
            catalog = author.collections[0]
            catalog_title = catalog.title
            subject_id = catalog.subject_no
            subject = Subject.query.get(subject_id)
            subject_name = subject.name

            tanggal = None
            # Ambil data dari sesi atau dari database sesuai kebutuhan
            nama = first_name + ' ' + last_name
            nim = student.nim

            
            #subject = session.get('subject')

            # Render template HTML dengan data
            rendered_html = render_template('pdf_template.html', nama=nama, nim=nim, title=catalog_title, subject_name=subject_name)

            # Konversi HTML ke PDF
            #pdfkit.from_file('rendered_template.html', 'rendered_template.pdf')

            # Kirim file PDF sebagai respons
            # with open('rendered_template.pdf', 'rb') as f:
            #     pdf_data = f.read()
            
            response_string = pdfkit.from_string(rendered_html, False, options={'--enable-local-file-access': True})
            
            response = make_response(response_string)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = 'inline; filename=download.pdf'
            
            return response
    else:
        return redirect(url_for('login'))

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)
