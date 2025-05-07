from typing import List
from flask import Flask, render_template, request, redirect, url_for, request, session, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import sqlalchemy
import bcrypt
import os
import uuid
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




class File(db.Model):
    id: int = db.Column(db.Integer, primary_key=True)
    
    filename: str = db.Column(db.String(255), unique=True)
    original_filename: str = db.Column(db.String(255))

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
        return os.path.join(app.config['UPLOAD_DIRECTORY'], self.filename)

    @property
    def file(self):
        return send_from_directory(app.config['UPLOAD_DIRECTORY'], self.filename)
    
    @file.setter
    def file(self, file):
        # Simpan nama file asli
        self.original_filename = file.filename
        
        # Buat nama file yang aman
        filename = secure_filename(file.filename)
        
        # Tambahkan timestamp untuk menghindari nama yang sama
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{timestamp}_{filename}"
        
        file.save(os.path.join(app.config['UPLOAD_DIRECTORY'], filename))
        self.filename = filename 

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

    
    # @file.setter
    # def file(self, file):
    #     # File berasal dari form atau request
    #     extension = file.filename.rsplit('.', 1)[1].lower()
    #     filename = uuid.uuid4().hex + '.' + extension

    #     file.save(os.path.join(app.config['UPLOAD_DIRECTORY'], filename))
    #     self.filename = filename 

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
    # Query untuk mendapatkan semua subject
    subjects = Subject.query.all()

    # Query untuk koleksi terbaru
    latest_catalogs = db.session.query(
        Catalog, Person
    ).join(
        catalog_authors, Catalog.id == catalog_authors.c.catalog_id
    ).join(
        Author, catalog_authors.c.author_id == Author.person_id
    ).join(
        Person, Author.person_id == Person.id
    ).filter(
        Catalog.is_opac == 1  # Tambahkan filter ini
    ).order_by(
        Catalog.id.desc()
    ).limit(6).all()

    return render_template('index.html', subjects=subjects, latest_catalogs=latest_catalogs)


@app.route("/show_detail_collection/<int:catalog_id>")
def show_detail_collection(catalog_id):
    # Query untuk mendapatkan detail catalog beserta data penulisnya
    catalog_detail = db.session.query(
        Catalog, Person
    ).join(
        catalog_authors, Catalog.id == catalog_authors.c.catalog_id
    ).join(
        Author, catalog_authors.c.author_id == Author.person_id
    ).join(
        Person, Author.person_id == Person.id
    ).filter(
        Catalog.id == catalog_id
    ).first()
    
    if not catalog_detail:
        flash('Katalog tidak ditemukan.')
        return redirect(url_for('index'))
        
    return render_template('show_detail_collection.html', catalog=catalog_detail[0], person=catalog_detail[1])

from sqlalchemy.orm import joinedload

@app.route("/search", methods=['GET'])
def search():
    query = request.args.get('query', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of items per page
    
    if not query:
        return redirect(url_for('index'))
        
    # Query untuk mencari berdasarkan title, nama, ISBN, dan subject.name
    search_results = db.session.query(
        Catalog, Person
    ).join(
        catalog_authors, Catalog.id == catalog_authors.c.catalog_id
    ).join(
        Author, catalog_authors.c.author_id == Author.person_id
    ).join(
        Person, Author.person_id == Person.id
    ).join(
        Subject, Catalog.subject_no == Subject.id
    ).filter(
        db.or_(
            Catalog.title.ilike(f'%{query}%'),
            Person.first_name.ilike(f'%{query}%'),
            Person.last_name.ilike(f'%{query}%'),
            Catalog.isbn.ilike(f'%{query}%'),
            Subject.name.ilike(f'%{query}%')  # Menambahkan pencarian berdasarkan subject.name
        )
    ).options(
        joinedload(Catalog.subject)  # Memuat Subject dalam hasil query
    ).order_by(Catalog.id.desc())

    # Get total count for pagination
    total_results = search_results.count()
    
    # Apply pagination
    paginated_results = search_results.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('search_results.html', 
                         results=paginated_results.items,
                         query=query,
                         result_count=total_results,
                         pagination=paginated_results)


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
            # Ambil semua permission_id yang dimiliki user dari role_permissions
            permission_ids = [perm.id for perm in user.role.permissions]

            session['permissions'] = permission_ids  # Simpan dalam session
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
                page = request.args.get('page', 1, type=int)
                per_page = 10  # Number of items per page

                # Query to get only students who have submitted catalogs with pagination
                # students_query = (
                #     Student.query
                #     .join(Person)
                #     .join(Author, Person.id == Author.person_id)
                #     .join(Author.collections)
                #     .order_by(Catalog.id.desc())
                #     .distinct()
                # )
                students_query_base = (
                    Student.query
                    .join(Person)
                    .join(Author, Person.id == Author.person_id)
                    .join(Author.collections)
                )

                # Get total count
                # total_students = students_query.count()
                total_students = students_query_base.distinct().count()

                # Apply pagination
                # paginated_students = students_query.paginate(page=page, per_page=per_page, error_out=False)
                paginated_students = students_query_base.order_by(Catalog.id.desc()).distinct().paginate(page=page, per_page=per_page, error_out=False)
                return render_template('dashboard_admin.html', 
                                    students=paginated_students.items,
                                    pagination=paginated_students,
                                    total_count=total_students)
            elif user.role_id == 2:
                # Rest of the existing code for role_id == 2...
                person = Person.query.filter_by(user_id=user.id).first()
                author = Author.query.filter_by(person_id=person.id).first()
                student = Student.query.filter_by(person_id=person.id).first()
                status_catalog = None
                reject_status = False
                description = ""
                checked_items = {}
                item_list = [
                    {"key": "reject", "label": "Reject"},
                    {"key": "sampul", "label": "Sampul"},
                    {"key": "halaman_judul", "label": "Halaman Judul"},
                    {"key": "lembar_pengesahan", "label": "Lembar Pengesahan dengan Tanda Tangan dan Stempel Basah"},
                    {"key": "pernyataan_keaslian", "label": "Pernyataan Keaslian beserta Materai"},
                    {"key": "kata_pengantar", "label": "Kata Pengantar / Daftar Isi"},
                    {"key": "abstrak", "label": "Abstrak"},
                    {"key": "bab_1_4", "label": "Bab 1/4"},
                    {"key": "daftar_pustaka", "label": "Daftar Pustaka"},
                    {"key": "lampiran", "label": "Lampiran"}
                ]
                name = person.first_name + ' ' + person.last_name
                if author and author.collections:
                    catalog = author.collections[0]
                    status_catalog = catalog.status
                    reject_status = catalog.reject_status
                    checked_items = catalog.checked_items
                    description = catalog.description

                return render_template('dashboard_student.html', 
                                    status_catalog=status_catalog, 
                                    name=name,
                                    reject_status=reject_status, 
                                    checked_items=checked_items,
                                    item_list=item_list, 
                                    description=description)
            elif user.role_id == 3:
                if user.role_id != 3:
                    return redirect(url_for('login.html'))
                return render_template('dashboard_s_admin.html')

            elif user.role_id == 4:
                if user.role_id != 4:
                    return redirect(url_for('login.html'))
                return render_template('collections.html')
            else:
                flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
                return redirect(url_for('login'))
        else:
            flash('Pengguna tidak ditemukan.')
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


# Add these routes to app.py for user management functionality

@app.route('/manage_users')
def manage_users():
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 3:  # Only super admin (role_id 3) can access
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Query to get all users with pagination
    query = request.args.get('query', '')
    
    if query:
        users_query = User.query.join(Person).filter(
            db.or_(
                Person.first_name.ilike(f'%{query}%'),
                Person.last_name.ilike(f'%{query}%'),
                User.email.ilike(f'%{query}%')
            )
        ).order_by(User.id.desc())
    else:
        users_query = User.query.order_by(User.id.desc())
    
    # Get total count
    total_users = users_query.count()
    
    # Apply pagination
    paginated_users = users_query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get all roles for the dropdown
    roles = Role.query.all()
    
    return render_template('manage_users.html', 
                          users=paginated_users.items,
                          pagination=paginated_users,
                          total_count=total_users,
                          roles=roles,
                          query=query)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 3:  # Only super admin can access
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('dashboard'))
    
    # Get all roles for the dropdown
    roles = Role.query.all()
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        role_id = request.form['role_id']
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email sudah terdaftar. Silakan gunakan email lain.', 'danger')
            return render_template('add_user.html', roles=roles)
        
        # Create new user
        role = Role.query.get(role_id)
        if not role:
            flash('Role tidak valid.', 'danger')
            return render_template('add_user.html', roles=roles)
        
        # Create new user with hashed password
        new_user = User(email=email, role=role)
        new_user.password = password  # This will use the password property setter to hash
        
        # Create Person object
        person = Person(first_name=first_name, last_name=last_name, user=new_user)
        
        # If role is student, create Student object with NIM
        if int(role_id) == 2:  # Assuming role_id 2 is for students
            nim = request.form.get('nim')
            if not nim:
                flash('NIM diperlukan untuk akun mahasiswa.', 'danger')
                return render_template('add_user.html', roles=roles)
            
            student = Student(nim=nim, person=person)
            
            # Create Author object linked to Person
            author = Author(person=person)
        
        # If role is staff, create Staff object with NIP
        elif int(role_id) == 1 or int(role_id) == 3 or int(role_id) == 4:  # Admin or Staff role
            nip = request.form.get('nip')
            if not nip:
                flash('NIP diperlukan untuk akun staf.', 'danger')
                return render_template('add_user.html', roles=roles)
            
            staff = Staff(nip=nip, person=person)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User berhasil ditambahkan.', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'danger')
    
    return render_template('add_user.html', roles=roles)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user or current_user.role_id != 3:  # Only super admin can access
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    person = Person.query.filter_by(user_id=user.id).first()
    
    # Get student or staff data if exists
    student = None
    staff = None
    
    if person:
        student = Student.query.filter_by(person_id=person.id).first()
        staff = Staff.query.filter_by(person_id=person.id).first()
    
    # Get all roles for the dropdown
    roles = Role.query.all()
    
    if request.method == 'POST':
        user.email = request.form['email']
        
        # Update password if provided
        new_password = request.form.get('password')
        if new_password and new_password.strip():
            user.password = new_password
        
        # Update role
        new_role_id = request.form['role_id']
        if int(new_role_id) != user.role_id:
            user.role_id = new_role_id
        
        # Update person data
        if person:
            person.first_name = request.form['first_name']
            person.last_name = request.form['last_name']
            
            # Handle student/staff data based on role
            if int(new_role_id) == 2:  # Student role
                if not student:
                    # Create student record if switching to student role
                    nim = request.form.get('nim')
                    if not nim:
                        flash('NIM diperlukan untuk akun mahasiswa.', 'danger')
                        return render_template('edit_user.html', user=user, person=person, 
                                              student=student, staff=staff, roles=roles)
                    
                    student = Student(nim=nim, person=person)
                    
                    # Create Author object if not exists
                    author = Author.query.filter_by(person_id=person.id).first()
                    if not author:
                        author = Author(person=person)
                else:
                    # Update existing student record
                    student.nim = request.form.get('nim')
            
            elif int(new_role_id) in [1, 3, 4]:  # Admin or Staff roles
                if not staff:
                    # Create staff record if switching to staff role
                    nip = request.form.get('nip')
                    if not nip:
                        flash('NIP diperlukan untuk akun staf.', 'danger')
                        return render_template('edit_user.html', user=user, person=person, 
                                              student=student, staff=staff, roles=roles)
                    
                    staff = Staff(nip=nip, person=person)
                else:
                    # Update existing staff record
                    staff.nip = request.form.get('nip')
        
        try:
            db.session.commit()
            flash('User berhasil diperbarui.', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'danger')
    
    return render_template('edit_user.html', user=user, person=person, 
                          student=student, staff=staff, roles=roles)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user or current_user.role_id != 3:  # Only super admin can access
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('dashboard'))
    
    # Prevent deleting yourself
    if user_id == current_user.id:
        flash('Anda tidak dapat menghapus akun Anda sendiri.', 'danger')
        return redirect(url_for('manage_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(user)  # This will cascade delete related records
        db.session.commit()
        flash('User berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Terjadi kesalahan: {str(e)}', 'danger')
    
    return redirect(url_for('manage_users'))

@app.route('/api/search', methods=['GET'])
def api_search():
    query = request.args.get('query', '')
    students_query = (
        Student.query
        .join(Person)
        .join(Author, Person.id == Author.person_id)
        .join(Author.collections)
        .filter(
            db.or_(
                Person.first_name.ilike(f'%{query}%'),
                Person.last_name.ilike(f'%{query}%'),
                Catalog.title.ilike(f'%{query}%')
            )
        )
        .distinct()
    )
    students = []
    for student in students_query:
        catalog = student.person.author.collections[0]
        status = 'Pending'
        status_class = 'warning text-dark'
        if catalog.status == 1:
            status = 'Accept'
            status_class = 'success'
        elif catalog.status == 2:
            status = 'Reject'
            status_class = 'danger'
        
        students.append({
            'name': f"{student.person.first_name} {student.person.last_name}",
            'title': catalog.title,
            'status': status,
            'status_class': status_class,
            'edit_url': url_for('edit_student', student_id=student.person_id)
        })
    return {'students': students}


@app.route('/edit_student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 1:
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('login'))

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
                catalog.is_opac=1
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

def generate_call_no(subject_name: str, publish_year: int, author_name: str, title: str) -> str:
    # Extract education level and subject code
    if subject_name.startswith('S1'):
        level = 'SKR'
    elif subject_name.startswith('S2'):
        level = 'S2'
    elif subject_name.startswith('S3'):
        level = 'S3'
    else:
        level = 'SKR'  # Default to SKR if not specified
    
    # Extract subject code (assuming format "SX-Subject Name")
    subject_parts = subject_name.split('-', 1)
    if len(subject_parts) > 1:
        subject_code = ''.join(word[0].upper() for word in subject_parts[1].split())[:2]
    else:
        subject_code = 'XX'  # Default if no subject code can be extracted
    
    # Get last 2 digits of year
    year_suffix = str(publish_year)[-2:]
    
    # Get first 3 letters of author name (uppercase)
    author_code = author_name.strip().upper()[:3]
    
    # Get first letter of title (lowercase)
    title_code = title.strip()[0].lower()
    
    # Construct call_no
    call_no = f"{level}-{subject_code}{year_suffix} {author_code} {title_code}"
    
    return call_no

# Update the collections route in app.py

@app.route('/collections', methods=['GET'])
def collections():
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 4:
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('login'))
    # Only process search if there's a query parameter
    query = request.args.get('query', '')
    results = None
    pagination = None
    total_results = 0
    
    if query:  # Only perform search if there's a query
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Query untuk mencari berdasarkan title, nama, ISBN
        search_results = db.session.query(
            Catalog, Person
        ).join(
            catalog_authors, Catalog.id == catalog_authors.c.catalog_id
        ).join(
            Author, catalog_authors.c.author_id == Author.person_id
        ).join(
            Person, Author.person_id == Person.id
        ).filter(
            db.or_(
                Catalog.title.ilike(f'%{query}%'),
                Person.first_name.ilike(f'%{query}%'),
                Person.last_name.ilike(f'%{query}%'),
                Catalog.isbn.ilike(f'%{query}%')
            )
        ).order_by(Catalog.id.desc())
        
        total_results = search_results.count()
        pagination = search_results.paginate(page=page, per_page=per_page, error_out=False)
        results = pagination.items
    
    return render_template('collections.html', 
                         query=query,
                         results=results,
                         pagination=pagination,
                         total_results=total_results)

@app.route('/collection_detail/<int:catalog_id>')
def collection_detail(catalog_id):
    if 'user_id' not in session:
        flash('Anda harus login terlebih dahulu.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role_id != 4:
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.')
        return redirect(url_for('login'))
    # Query untuk mendapatkan detail catalog beserta data penulisnya
    catalog_detail = db.session.query(
        Catalog, Person
    ).join(
        catalog_authors, Catalog.id == catalog_authors.c.catalog_id
    ).join(
        Author, catalog_authors.c.author_id == Author.person_id
    ).join(
        Person, Author.person_id == Person.id
    ).filter(
        Catalog.id == catalog_id
    ).first()
    
    if not catalog_detail:
        flash('Katalog tidak ditemukan.')
        return redirect(url_for('collections'))
    
    # Get the subject
    subject = Subject.query.get(catalog_detail[0].subject_no)
    
    return render_template('collection_detail.html', 
                         catalog=catalog_detail[0], 
                         person=catalog_detail[1],
                         subject=subject)

@app.route('/view_pdf/<int:student_id>')
def view_pdf(student_id):
    student = Student.query.get_or_404(student_id)
    person = Person.query.get(student.person_id)
    author = Author.query.filter_by(person_id=person.id).first()
    catalog = Catalog.query.join(Author, Catalog.authors).filter(Author.person_id == person.id).first()

    if catalog and catalog.file and catalog.file.file:
        response = make_response(catalog.file.file)
        response.headers['Content-Type'] = 'application/pdf'
        # Menambahkan header untuk mencegah caching
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        # Header untuk mencegah download
        response.headers['Content-Disposition'] = 'inline'
        return response
    else:
        return "File tidak tersedia", 404

@app.route('/formulir_collection', methods=['GET', 'POST'])
def formulir_collection():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    if not user or user.role_id != 2:  # Check if the user is a student
        flash('Anda tidak memiliki akses ke halaman ini.')
        return redirect(url_for('dashboard'))
        
    # Initialize default values
    person = Person.query.filter_by(user_id=user.id).first()
    student = Student.query.filter_by(person_id=person.id).first()
    author = Author.query.filter_by(person_id=person.id).first()
    catalog = None
    
    # Set default values
    nama_default = f"{person.first_name} {person.last_name if person.last_name else ''}"
    nim_default = student.nim if student else ''
    status_catalog = None
    catalog_title = None
    subject_name = None
    abstract = None
    reject_status = False

    # Check if author exists and has collections
    if author and author.collections:
        catalog = author.collections[0]
        catalog_title = catalog.title
        subject = Subject.query.get(catalog.subject_no)
        subject_name = subject.name if subject else None
        status_catalog = 0
        abstract = catalog.abstract
        reject_status = catalog.reject_status

    if request.method == 'POST':
        # Get form data
        nama = request.form['nama']
        nim = request.form['nim']
        judul_penelitian = request.form['judul_penelitian']
        prodi = request.form['prodi']
        abstract = request.form['abstract']
        pdf_file = request.files['pdf_file']

        if pdf_file and pdf_file.filename:
            try:
                # Create or get FileType
                file_type = FileType.query.filter_by(name='Skripsi').first()
                
                # Create new file object
                new_file_obj = File(pdf_file, file_type)
                db.session.add(new_file_obj)
                db.session.flush()
                new_file_obj.user = user

                # Get current year
                today = datetime.now()
                now_year = today.year

                # Get or create author if not exists
                if not author:
                    author = Author(person=person)
                    db.session.add(author)
                    db.session.commit()

                # Get subject
                subject = Subject.query.filter_by(name=prodi).first()
                if not subject:
                    print('Prodi tidak ditemukan.')
                    return redirect(url_for('formulir_collection'))

                # Get publisher
                publisher = Publisher.query.get(1)  # Assuming this is Universitas Hasanuddin
                if not publisher:
                    print('Publisher tidak ditemukan.')
                    return redirect(url_for('formulir_collection'))

                # Generate call_no
                call_no = generate_call_no(
                    subject_name=prodi,
                    publish_year=now_year,
                    author_name=nama,
                    title=judul_penelitian
                )

                if catalog:
                    # Update existing catalog
                    catalog.title = judul_penelitian
                    catalog.isbn = nim
                    catalog.abstract = abstract
                    catalog.subject = subject
                    catalog.publish_year = now_year
                    catalog.call_no = call_no
                    
                    # Handle file replacement
                    if catalog.file:
                        old_file = catalog.file
                        catalog.file = new_file_obj
                        old_file.delete_file()
                    else:
                        catalog.file = new_file_obj
                    
                    catalog.reject_status = False
                    catalog.status = 0
                else:
                    # Create new catalog
                    catalog = Catalog(
                        title=judul_penelitian,
                        isbn=nim,
                        abstract=abstract,
                        language_code='ind',
                        is_opac=False,
                        authors=[author],
                        subject=subject,
                        publisher=publisher,
                        publish_year=now_year,
                        file=new_file_obj,
                        call_no=call_no
                    )
                    db.session.add(catalog)

                # Create collection if it doesn't exist
                if not catalog.collections:
                    collection = Collection(
                        barcode_no=nim,
                        registration_no=nim,
                        call_no=call_no,
                        is_opac=True,
                        catalog=catalog
                    )
                    db.session.add(collection)

                db.session.commit()
                flash('Data berhasil disimpan.')
                return redirect(url_for('dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'Terjadi kesalahan: {str(e)}')
                return redirect(url_for('formulir_collection'))

    return render_template(
        'formulir_collection.html',
        nama_default=nama_default,
        nim_default=nim_default,
        status_catalog=status_catalog,
        catalog_title=catalog_title,
        subject_name=subject_name,
        abstract=abstract,
        reject_status=reject_status
    )


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

            tanggal = datetime.now().strftime("%d/%m/%y")
            print(tanggal)
            # Ambil data dari sesi atau dari database sesuai kebutuhan
            nama = first_name + ' ' + last_name
            nim = student.nim

            
            #subject = session.get('subject')

            # Render template HTML dengan data
            rendered_html = render_template('pdf_template.html', nama=nama, nim=nim, title=catalog_title, subject_name=subject_name,tanggal=tanggal)

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
