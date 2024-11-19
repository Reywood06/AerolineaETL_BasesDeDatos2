from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from wtforms.fields import DateField
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import ValidationError

import pyodbc  # Para SQL Server
import psycopg2  # Para PostgreSQL
import mysql.connector  # Para MySQL

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi_clave_secreta'

@app.route('/')
def home():
    return redirect(url_for('login'))

#Conexion para MySQL
MySQLConexion = mysql.connector.connect(
    user = "jesanchezv", 
    password = "Admin1234",
    host = "vuelos.mysql.database.azure.com",
    database = "vuelos"
)

print(MySQLConexion)

#Conexion para PostgreSQL
PostgreSQLConexion = psycopg2.connect(
    host="registrosusuarios.postgres.database.azure.com",
    database="registros_usuarios",
    user="jesanchezv",
    password="Admin1234",
    port="5432"
)

print(PostgreSQLConexion)


# Conexion para SQL Server
SQLServer_Name = 'mysql-server1.database.windows.net'
SQLServer_database = 'Vuelos_programados'
SQLServer_username = 'jesanchezv'
SQLServer_password = 'Admin1234'
SQLServer_driver = 'ODBC Driver 17 for SQL Server'

# Asegúrate de que la cadena de conexión esté correctamente formada
SQLServer_connection_string = f'DRIVER={SQLServer_driver};SERVER={SQLServer_Name};DATABASE={SQLServer_database};UID={SQLServer_username};PWD={SQLServer_password};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'

try:
    SQLServerConexion = pyodbc.connect(SQLServer_connection_string)
    print("Conexión exitosa a Azure SQL Server")
except Exception as e:
    print("Error en la conexión: ", e)

    
# Clase de usuario
class Usuario(UserMixin):
    def __init__(self, id, nombre, contrasena, correo, cedula):
        self.id = id
        self.nombre = nombre
        self.contrasena = contrasena
        self.correo = correo
        self.cedula = cedula

# Diccionario de usuarios, que inicialmente contiene solo el usuario 'admin'
usuarios = {
    'admin': Usuario('admin', 'admin', generate_password_hash('12345'), 'admin@ejemplo.com', '12345678')
}

# Conjuntos para cédulas y correos ya registrados
cedulas = set()
correos = set()

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Función user_loader
@login_manager.user_loader
def load_user(user_id):
    # Buscar el usuario por su id (nombre de usuario)
    return usuarios.get(user_id)  # Devuelve el usuario si lo encuentra, o None

paises = {
    "Colombia": ["Bogotá", "Medellín", "Cali"],
    "México": ["CDMX", "Guadalajara", "Monterrey"],
    "Argentina": ["Buenos Aires", "Córdoba", "Mendoza"],
    "España": ["Madrid", "Barcelona", "Sevilla"],
    "Chile": ["Santiago", "Valparaíso", "Concepción"]
}

vuelos = [
    {"origen": "Colombia", "destino": "México", "precio": "$500", "duracion": "5h", "escalas": 0},
    {"origen": "México", "destino": "España", "precio": "$700", "duracion": "10h", "escalas": 1},
    {"origen": "Colombia", "destino": "Argentina", "precio": "$600", "duracion": "7h", "escalas": 1},
    {"origen": "España", "destino": "Chile", "precio": "$800", "duracion": "12h", "escalas": 2}
]


# Formulario de login
class LoginForm(FlaskForm):
    nombre = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=50)])
    contrasena = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar sesión')

# Formulario de registro
class RegistroForm(FlaskForm):
    nombres = StringField('Nombres', validators=[DataRequired(), Length(min=2, max=100)])
    apellidos = StringField('Apellidos', validators=[DataRequired(), Length(min=2, max=100)])
    pais = SelectField('País', choices=[ 
        ('', 'Selecciona tu país'),
        ('Colombia', 'Colombia'),
        ('México', 'México'),
        ('Argentina', 'Argentina'),
        ('España', 'España'),
        ('Chile', 'Chile')
    ], validators=[DataRequired()])
    fecha_nacimiento = DateField('Fecha de nacimiento', format='%Y-%m-%d', validators=[DataRequired()])
    celular = StringField('Número de celular', validators=[DataRequired(), Length(min=10, max=15)])
    correo = StringField('Correo electrónico', validators=[DataRequired(), Email()])
    cedula = StringField('Cédula', validators=[DataRequired(), Length(min=8, max=20)])
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=4, max=50)])
    contrasena = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    confirmar_contrasena = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('contrasena', message="Las contraseñas deben coincidir.")])
    submit = SubmitField('Registrarse')

    # Validación de mayor de edad
    def validate_fecha_nacimiento(self, field):
        edad_minima = 18
        fecha_nacimiento = field.data
        hoy = datetime.today()
        edad = hoy.year - fecha_nacimiento.year - ((hoy.month, hoy.day) < (fecha_nacimiento.month, fecha_nacimiento.day))
        if edad < edad_minima:
            raise ValidationError('Debes ser mayor de edad para registrarte.')

    # Validación de cédula única
    def validate_cedula(self, field):
        if field.data in cedulas:
            raise ValidationError('Esta cédula ya está registrada.')

    # Validación de correo único
    def validate_correo(self, field):
        if field.data in correos:
            raise ValidationError('Este correo electrónico ya está registrado.')

# Definición del formulario con Flask-WTF
class FiltroVueloForm(FlaskForm):
    pais_origen = SelectField('País de Origen', choices=[], validators=[DataRequired()])
    pais_destino = SelectField('País de Destino', choices=[], validators=[DataRequired()])
    submit = SubmitField('Buscar')


# Rutas de las páginas
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Verificar si el usuario existe en el diccionario
        usuario = usuarios.get(form.nombre.data)
        if usuario:
            # Verificar si la contraseña es correcta
            if check_password_hash(usuario.contrasena, form.contrasena.data):
                login_user(usuario)
                return redirect(url_for('ofertas'))
            else:
                flash('Contraseña incorrecta', 'danger')
        else:
            flash('Nombre de usuario no encontrado', 'danger')
    return render_template('login.html', form=form)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegistroForm()
    if form.validate_on_submit():
        # Verificar que la cédula y correo no estén registrados
        if form.cedula.data in cedulas:
            flash('Esta cédula ya está registrada', 'danger')
        elif form.correo.data in correos:
            flash('Este correo electrónico ya está registrado', 'danger')
        else:
            nuevo_usuario = Usuario(
                form.nombre_usuario.data,
                form.nombre_usuario.data,
                generate_password_hash(form.contrasena.data),
                form.correo.data,
                form.cedula.data
            )
            usuarios[form.nombre_usuario.data] = nuevo_usuario
            cedulas.add(form.cedula.data)  # Registrar cédula
            correos.add(form.correo.data)  # Registrar correo
            flash('Registrado correctamente. Puedes iniciar sesión ahora.', 'success')
            return redirect(url_for('login'))
    return render_template('registro.html', form=form)


@app.route('/ofertas', methods=['GET', 'POST'])
@login_required
def ofertas():
    form = FiltroVueloForm()

    # Inicializar las variables para vuelos filtrados y ciudades
    vuelos_filtrados = []
    ciudades_origen = []
    ciudades_destino = []

    # Solo filtrar si el formulario es válido
    if form.validate_on_submit():
        origen_seleccionado = form.pais_origen.data
        destino_seleccionado = form.pais_destino.data
        
        # Cargar las ciudades disponibles para el país de origen y destino
        ciudades_origen = paises.get(origen_seleccionado, [])
        ciudades_destino = paises.get(destino_seleccionado, [])
        
        # Filtrar vuelos solo si ambos países de origen y destino están seleccionados
        if origen_seleccionado and destino_seleccionado:
            vuelos_filtrados = [
                vuelo for vuelo in vuelos 
                if vuelo['origen'] == origen_seleccionado and vuelo['destino'] == destino_seleccionado
            ]
    
    # Rellenar las opciones de los países en el formulario
    form.pais_origen.choices = [(pais, pais) for pais in paises.keys()]
    form.pais_destino.choices = [(pais, pais) for pais in paises.keys()]

    # Retornar la plantilla con los vuelos filtrados y las ciudades
    return render_template('ofertas.html', 
                           form=form, 
                           vuelos=vuelos_filtrados, 
                           ciudades_origen=ciudades_origen, 
                           ciudades_destino=ciudades_destino, 
                           paises=paises)



if __name__ == '__main__':
    app.run(debug=True)
