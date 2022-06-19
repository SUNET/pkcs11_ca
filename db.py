import psycopg2

import config
import ca

# BAD, sql injection vulnerable
# cur.execute("INSERT INTO serial(serial) VALUES(" + str(curr_serial) + ")")
# Much better!
#sql_q = 'INSERT INTO serial(serial) VALUES(%s)'
#cur.execute(sql_q, (curr_serial,))
    

def get_con():
    con = psycopg2.connect(database=config.DB_DATABASE,
                           user=config.DB_USER,
                           password=config.DB_PASSWORD,
                           host=config.DB_HOST,
                           port=config.DB_PORT,
                           connect_timeout=config.DB_TIMEOUT,
                           )
    
    return con

def drop_tables():
    con = get_con()
    with con:
        cur = con.cursor()
        
        cur.execute('''DROP TABLE IF EXISTS crl CASCADE''')
        cur.execute('''DROP TABLE IF EXISTS cert CASCADE''')
        cur.execute('''DROP TABLE IF EXISTS csr CASCADE''')
        
        cur.execute('''DROP TABLE IF EXISTS serial CASCADE''')
        cur.execute('''DROP TABLE IF EXISTS fingerprint CASCADE''')
        cur.execute('''DROP TABLE IF EXISTS author CASCADE''')

        con.commit()
        cur.close()
    con.close()
    
        
def start():
    con = get_con()
    with con:
        cur = con.cursor()
        
        cur.execute('''CREATE TABLE IF NOT EXISTS serial
        (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, serial TEXT UNIQUE NOT NULL)''')

        cur.execute('''CREATE TABLE IF NOT EXISTS fingerprint
        (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL)''')

        cur.execute('''CREATE TABLE IF NOT EXISTS author
        (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, fingerprint TEXT UNIQUE NOT NULL, ip TEXT NOT NULL)''')
    
        cur.execute('''CREATE TABLE IF NOT EXISTS csr
        (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, pem TEXT UNIQUE NOT NULL, date_received TEXT NOT NULL, author BIGINT NOT NULL REFERENCES author(id))''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS cert
        (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, csr BIGINT UNIQUE NOT NULL REFERENCES csr(id), serial BIGINT UNIQUE NOT NULL REFERENCES serial(id), pem TEXT UNIQUE NOT NULL, date_issued TEXT NOT NULL, date_expire TEXT NOT NULL, fingerprint BIGINT UNIQUE NOT NULL REFERENCES fingerprint(id), author BIGINT NOT NULL REFERENCES author(id))''')

        cur.execute('''CREATE TABLE IF NOT EXISTS crl
        (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, pem TEXT UNIQUE NOT NULL, last_update TEXT NOT NULL, next_update TEXT NOT NULL, author BIGINT NOT NULL REFERENCES author(id))''')

    
        # FIXME SET OUT CA as real author
        sql_q = 'INSERT INTO author(name, fingerprint, ip) VALUES(%s, %s, %s) ON CONFLICT (fingerprint) DO NOTHING'
        cur.execute(sql_q, (config.ca_info_common_name, ca.fingerprint(), "123.123.123.123",))
    
        con.commit()
        cur.close()
    con.close()

def issued_certs():
    con = get_con()
    with con:
        cur = con.cursor()

        sql_q = 'SELECT pem FROM cert'
        cur.execute(sql_q,)
        ret = cur.fetchall()
        cur.close()
    con.close()
        
    certs = []
    for c in ret:
        certs.append(c[0])
        
    return certs

# Every cert has a serial so lets check for the serial
def cert_exists(curr_serial):
    con = get_con()
    with con:
        cur = con.cursor()

        sql_q = 'SELECT COUNT(serial) FROM serial where serial = %s'
        cur.execute(sql_q, (curr_serial,))
        ret = cur.fetchone()[0]
        
        cur.close()
    con.close()
    
    return ret > 0


def issued_serials():
    con = get_con()
    with con:
        cur = con.cursor()

        sql_q = 'SELECT serial FROM serial'
        cur.execute(sql_q,)
        ret = cur.fetchall()
        cur.close()
    con.close()
    
    serials = []
    for s in ret:
        serials.append(s[0])
        
    return serials
    
def serial_exists(curr_serial):
    con = get_con()
    with con:
        cur = con.cursor()

        sql_q = 'SELECT COUNT(serial) FROM serial where serial = %s'
        cur.execute(sql_q, (curr_serial,))
        ret = cur.fetchone()[0]
        
        cur.close()
    con.close()
    
    return ret > 0

def load_crl():
    con = get_con()
    with con:
        cur = con.cursor()

        sql_q = 'SELECT pem FROM crl WHERE id = (SELECT MAX(id) FROM crl)'
        cur.execute(sql_q,)
        ret = cur.fetchone()[0]
        cur.close()
    con.close()
        
    return ret

def save_crl(curr_pem, last_update, next_update, curr_author):
    con = get_con()
    with con:
        cur = con.cursor()

        sql_q = 'INSERT INTO crl(pem, last_update, next_update, author) VALUES(%s, %s, %s, %s) RETURNING id'
        cur.execute(sql_q, (curr_pem, last_update, next_update, curr_author,))
        id_crl = cur.fetchone()[0]

        con.commit()
        cur.close()
    con.close()
    
    return id_crl
    
def save_csr(curr_pem, date_received, curr_author):
    con = get_con()
    with con:
        cur = con.cursor()
    
        sql_q = 'INSERT INTO csr(pem, date_received, author) VALUES(%s, %s, %s) RETURNING id'
        cur.execute(sql_q, (curr_pem, date_received, curr_author,))
        id_csr = cur.fetchone()[0]
        
        con.commit()
        cur.close()
    con.close()
        
    return id_csr
    
def save_cert(curr_serial, id_csr, curr_pem, curr_issued, curr_expire, curr_fingerprint, curr_author):
    con = get_con()
    with con:
        cur = con.cursor()
    
        sql_q = 'INSERT INTO serial(serial) VALUES(%s) RETURNING id'
        cur.execute(sql_q, (curr_serial,))
        id_serial = cur.fetchone()[0]
    
        sql_q = 'INSERT INTO fingerprint(fingerprint) VALUES(%s) RETURNING id'
        cur.execute(sql_q, (curr_fingerprint,))
        id_fingerprint = cur.fetchone()[0]

        # FIXME same for author
    
        sql_q = 'INSERT INTO cert(serial, csr, pem, date_issued, date_expire, fingerprint, author) VALUES(%s, %s, %s, %s, %s, %s, %s)'
        cur.execute(sql_q, (id_serial,
                            id_csr,
                            curr_pem,
                            curr_issued,
                            curr_expire,
                            id_fingerprint,
                            1,)) #FIXME curr_author,))


        con.commit()
        cur.close()
    con.close()
    
