// Prueba de lib/clave.js y del cifrado de los almacenes, sin Electron real.
//
// POR QUE EXISTE: la clave de cifrado en disco solia estar escrita en el
// codigo. Al publicar el agente eso dejo de servir (una clave en un repo
// publico es una clave que cualquiera lee), asi que ahora se genera una por
// instalacion y la protege el sistema operativo. Esta prueba fija ese
// contrato: que la clave no vuelva nunca al codigo, que no se comparta entre
// instalaciones, y que los archivos de la version vieja se borren.
//
// Correr con: npm test
const path = require('path'), fs = require('fs'), os = require('os'), Module = require('module');
const AGENT = path.join(__dirname, '..');
const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'agente-'));

let llaveroDisponible = true;
const electronFalso = {
  app: { getPath: () => userData, setLoginItemSettings(){}, quit(){} },
  safeStorage: {
    isEncryptionAvailable: () => llaveroDisponible,
    // "DPAPI" de juguete: cifra de verdad (XOR con una clave del "SO") para
    // que la prueba de "no queda en texto plano" mida el codigo y no el stub.
    encryptString: (s) => {
      const c = require('crypto');
      const iv = c.randomBytes(16);
      const ci = c.createCipheriv('aes-256-cbc', Buffer.alloc(32, 7), iv);
      return Buffer.concat([Buffer.from('OS:'), iv, ci.update(s, 'utf8'), ci.final()]);
    },
    decryptString: (b) => {
      const c = require('crypto');
      if (!b.slice(0,3).equals(Buffer.from('OS:'))) throw new Error('no es del llavero');
      const de = c.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 7), b.slice(3, 19));
      return Buffer.concat([de.update(b.slice(19)), de.final()]).toString('utf8');
    },
  },
  Notification: { isSupported: () => false },
};
// electron-store falso: guarda en JSON y RECHAZA si la clave no coincide.
class StoreFalso {
  constructor({ name, encryptionKey, defaults = {} }) {
    this.ruta = path.join(userData, `${name}.json`); this.k = encryptionKey; this.defaults = defaults;
    if (fs.existsSync(this.ruta)) {
      const d = JSON.parse(fs.readFileSync(this.ruta, 'utf8'));
      if (d.__k !== encryptionKey) throw new Error('clave incorrecta: no se puede descifrar');
      this.data = d;
    } else { this.data = { __k: encryptionKey, ...defaults }; this._flush(); }
  }
  _flush() { fs.writeFileSync(this.ruta, JSON.stringify(this.data)); }
  get(k, d) { return this.data[k] !== undefined ? this.data[k] : (d !== undefined ? d : this.defaults[k]); }
  set(k, v) { this.data[k] = v; this._flush(); }
  delete(k) { delete this.data[k]; this._flush(); }
}
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (req, ...a) {
  if (req === 'electron') return 'ELECTRON_FALSO';
  if (req === 'electron-log') return 'LOG_FALSO';
  if (req === 'electron-store') return 'STORE_FALSO';
  return origResolve.call(this, req, ...a);
};
require.cache['ELECTRON_FALSO'] = { id:'ELECTRON_FALSO', filename:'ELECTRON_FALSO', loaded:true, exports: electronFalso };
require.cache['LOG_FALSO'] = { id:'LOG_FALSO', filename:'LOG_FALSO', loaded:true, exports: { transports:{file:{},console:{}}, info(){}, warn(){}, error(){}, debug(){} } };
require.cache['STORE_FALSO'] = { id:'STORE_FALSO', filename:'STORE_FALSO', loaded:true, exports: StoreFalso };

const ok = (c, m) => { console.log(`${c ? '  OK  ' : ' FALLA'}  ${m}`); if (!c) process.exitCode = 1; };

// Simular una instalación VIEJA con la clave que estaba en el código.
const CLAVE_VIEJA = 'tr_pa_e7c1f4a9b2d6e0338f5a1c7d9b4e2f60a3c8d5e1f9b0264c';
for (const n of ['config','print-queue','audit-print','audit-pairing'])
  fs.writeFileSync(path.join(userData,`${n}.json`), JSON.stringify({ __k: CLAVE_VIEJA, pairedToken:'token-viejo-secreto' }));

const clave = require(path.join(AGENT,'lib/clave.js'));
const config = require(path.join(AGENT,'lib/config.js'));

console.log('\n== clave por instalación ==');
const k1 = clave.resolver();
ok(typeof k1 === 'string' && k1.length === 64, 'genera una clave de 256 bits');
ok(k1 !== CLAVE_VIEJA, 'NO es la clave que estaba en el código');
ok(clave.resolver() === k1, 'es estable dentro del mismo proceso');
ok(fs.existsSync(path.join(userData,'clave-almacen.bin')), 'la persiste en disco');
ok(fs.readFileSync(path.join(userData,'clave-almacen.bin')).slice(0,3).toString() === 'OS:', 'protegida por el llavero del SO');
ok(!fs.readFileSync(path.join(userData,'clave-almacen.bin')).toString('utf8').includes(k1), 'la clave NO queda en texto plano');

console.log('\n== borrado de los almacenes viejos ==');
config.limpiarAlmacenesViejos();
const quedan = ['config','print-queue','audit-print','audit-pairing'].filter(n => fs.existsSync(path.join(userData,`${n}.json`)));
ok(quedan.length === 0, `borra los 4 archivos cifrados con la clave vieja (quedan: ${quedan.length})`);

console.log('\n== el almacén nuevo funciona ==');
config.set('machineName','CAJA-01');
ok(config.get('machineName') === 'CAJA-01', 'guarda y lee');
const tok = config.generateAndSaveToken();
ok(tok.length === 64 && config.getPairedToken() === tok, 'genera y recupera el token de pairing');
ok(fs.existsSync(path.join(userData,'config-v2.json')), 'usa el archivo nuevo (config-v2)');
ok(!fs.existsSync(path.join(userData,'config.json')), 'no revive el archivo viejo');

console.log('\n== sin llavero del SO (Linux sin keyring) ==');
const userData2 = fs.mkdtempSync(path.join(os.tmpdir(), 'agente2-'));
electronFalso.app.getPath = () => userData2;
llaveroDisponible = false;
delete require.cache[path.join(AGENT,'lib/clave.js')];
const clave2 = require(path.join(AGENT,'lib/clave.js'));
const k2 = clave2.resolver();
ok(k2 !== k1, 'otra instalación => otra clave (no se comparte entre PCs)');
ok(fs.readFileSync(path.join(userData2,'clave-almacen.bin')).toString().startsWith('plano:'), 'cae al archivo restringido');
ok((fs.statSync(path.join(userData2,'clave-almacen.bin')).mode & 0o777) === 0o600, 'con permisos 600 (solo el dueño)');
ok(clave2.resolver() === k2, 'y la relee igual en el próximo arranque');
console.log('');
