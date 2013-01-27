"""Module par Skelon"""
import hashlib
import ssl
import struct
import threading
import time
import urllib.request as _requêteur

try:
    import requests as requêteur
except ImportError as ex:
    raise

class PrincipalSocket(threading.Thread):
    def __init__(self, serveur, psuedo_kikoo, mdp_kikoo, psuedo, salon, port, mdp = None):
        '''Socket du serveur principal.\nSi vous n'avez pas une compte pour joindre http://kikoo.formice.com/data.json, il faut demander Danley pour une compte.\nTigrounette change le serveur quand il veut. Vous devez donner l'IP avec le dernier de ".transformice.com"'''
        if not serveur.endswith('.transformice.com'):
            raise ValueError("Le serveur addresse faut dernier avec '.transformice.com'")
        else:
            self.serveur = serveur
        self.psuedo_kikoo = psuedo_kikoo
        self.mdp_kikoo = mdp_kikoo
        self.psuedo = (psuedo.encode('utf-8'))
        self.salon = (salon.encode('utf-8'))
        if mdp == None:
            self.mdp = (bytes())
        else:
            self.mdp = ((hashlib.sha256(mdp.encode('utf-8'))).hexdigest().encode('utf-8'))

        self.CCC = (bytes())
        self.fingerprint = (bytes())
        self.CMDTEC = (int())
        self.MDT = [(int())] * (int(10))
        self.connecté = (bool())
        self.principal = (ssl.SSLSocket())
        self.analyseur = (RecevoirThread.__init__(self))
        self.survivre = (DummyThread.__init__(self))

        try:
            self.principal.bind(('localhost', (int(port))))
        except ssl.socket_error as ex:
            raise

    def connecte(self, port):
        '''Pour connecter au serveur. Les ports ont autorisé: 3724, 443, 44440, 44444, 5555 ou 6112'''
        CCC = (struct.pack('>2B', (int(28)), (int(1))))
        with (list(((int(3724)), (int(443)), (int(44440)), (int(44444)), (int(5555)), (int(6112))))) as port_liste:
            try:
                if (int(port)) in port_liste:
                    self.principal.connect((self.serveur, port))
                    print('Connexion au serveur...')
                else:
                    raise ValueError("Révu: 3724, 443, 44440, 44444, 5555, 6112. Reçu: ", port)
            except ssl.socket_error as ex:
                raise

        try:
            ts, version, clé = (tuple(_requêteur.urlopen('http://kikoo.formice.com/data.txt').read().split(' ')))
            version = (struct.pack('>H', (int(version))))
            clé = ((struct.pack('>H', ((len(clé)) + 2))) + (clé.encode('utf-8')))
        except Exception as ex:
            raise

        chargeur = (struct.pack('>H', (int(0x17ed))))
        client = ((struct.pack('>H', ((len('StandAlone')) + 2))) + ('StandAlone'.encode('utf-8')))
        utilisateur = ((struct.pack('>H', ((len('-')) + 2))) + ('-'.encode('utf-8')))
        empty = ((struct.pack('>H', ((len(''))))) + (''.encode('utf-8')))
        fonte = ((struct.pack('>H', ((len('6c47bdb10f7d724677c7554211568d796934b8f057f81e202e0b65a1518b4a77') + 2))) + ('6c47bdb10f7d724677c7554211568d796934b8f057f81e202e0b65a1518b4a77'.encode('utf-8'))))
        string = ((struct.pack('>H', ((len('A=t&SA=t&SV=t&EV=t&MP3=t&AE=t&VE=t&ACC=f&PR=t&SP=f&SB=f&DEB=f&V=WIN 10,1,85,3&M=Adobe Windows&R=1366×768&COL=color&AR=1.0&OS=Windows7&ARCH=x86&L=fr&IME=t&PR32=t&PR64=f&PT=StandAlone&AVD=f&LFD=f&WD=f&TLS=t&ML=5.1&DP=72')) + 2))) + ('A=t&SA=t&SV=t&EV=t&MP3=t&AE=t&VE=t&ACC=f&PR=t&SP=f&SB=f&DEB=f&V=WIN 10,1,85,3&M=Adobe Windows&R=1366×768&COL=color&AR=1.0&OS=Windows7&ARCH=x86&L=fr&IME=t&PR32=t&PR64=f&PT=StandAlone&AVD=f&LFD=f&WD=f&TLS=t&ML=5.1&DP=72'.encode('utf-8')))
        paquet = (CCC + version + clé + chargeur + client + utilisateur + empty + fonte + string)
        self.envoyer(self, paquet, (bool()))
        self.analyseur.start()
        self.survivre.start()

        self.prendre_ccc(self, C = '28')
        langage = ((struct.pack('>H', ((len('fr')) + 2))) + ('fr'.encode('utf-8')))
        système = ((struct.pack('>H', ((len('Windows7')) + 2))) + ('Windows7'.encode('utf-8')))
        version_flash = ((struct.pack('>H', ((len('10,1,85,3')) + 2))) + ('10,1,85,3'.encode('utf-8')))
        paquet = (self.CCC + (struct.pack('>B', (int(17)))) + langage + système + version_flash)
        self.envoyer(self, paquet, (bool()))
        self._connecté = (bool(1))

    def préfixe(self):
        loc_5 = (int(self.CMDTEC % 9000 + 1000))
        self.fingerprint = (bytes())
        self.fingerprint += (struct.pack('>B', (int((self.MDT[int(loc_5 / 1000)])))))
        self.fingerprint += (struct.pack('>B', (int((self.MDT[int(loc_5 / 100) % 10])))))
        self.fingerprint += (struct.pack('>B', (int((self.MDT[int(loc_5 / 10) % 10])))))
        self.fingerprint += (struct.pack('>B', (int((self.MDT[loc_5 % 10])))))
        self.CMDTEC += (int(1))

        return self.fingerprint

    def ping(self):
        if self.connecté == (bool()):
            self.prendre_ccc(self, '26', '26')
            paquet = (self.CCC)
            self.envoyer(self, paquet, (bool()))
            paquet = (struct.pack('>2B', (int(26)), (int(26))))
            self.envoyer(self, paquet, (bool()))
        else:
            CCC = (struct.pack('>2B', (int(26)), (int(26))))
            paquet = (CCC)
            self.envoyer(self, paquet, (bool()))
            paquet = (struct.pack('>2B', (int(26)), (int(26))))
            self.envoyer(self, paquet, (bool(1)))

    def dummy(self):
        if self.connecté == (bool()):
            self.prendre_ccc(self, self.psuedo_kikoo, self.mdp_kikoo, '1', '1')
            paquet = (struct.pack('>2B', (int(26)), (int(2))))
            self.envoyer(self, paquet, (bool(1)))

        else:
            CCC = ((struct.pack('>H', ((len((struct.pack('>2B', (int(26)), (int(2)))))) + 2))) + (struct.pack('>2B', (int(26)), (int(2)))))
            paquet = (CCC)
            self.envoyer(self, paquet, (bool(1)))
            time.sleep(15)

    def communauté(self, communauté):
        '''0 = en, 1 = fr, 2 = ru, 3 = br, 4 = es, 5 = cn, 6 = tr, 7 = vk, 8 = pl, 9 = hu, 10 = nl, 11 = ro, 12 = id'''
        self.prendre_ccc(self, self.psuedo_kikoo, self.mdp_kikoo, '8', '2')
        try:
            paquet = (self.CCC + (struct.pack('>B', (int(communauté)))))
        except struct.error:
            raise ValueError("Révu un numéro.")
        self.envoyer(self, paquet, (bool()))

    def joindre(self):
        CCC = (struct.pack('>2B', (int(26)), (int(3))))
        paquet = (CCC + (struct.pack('>B', (int(1)))) + self.psuedo + (struct.pack('>B', (int(1)))) + self.mdp)
        self.envoyer(self, paquet, (bool(1)))

    def rejoindre(self):
        origin = ('http://www.transformice.com/Transformice.swf?n=1335716949138/[[DYNAMIC]]/1'.encode('utf-8'))
        paquet = ((struct.pack('>2B', (int(26)), (int(4)))) + (struct.pack('>B', (int(1)))) + self.psuedo + (struct.pack('>B', (int(1)))) + self.mdp + (struct.pack('>B', (int(1)))) + self.salon + (struct.pack('>B', (int(1)))) + origin)
        self.envoyer(self, paquet, (bool(1)))

    def prendre_ccc(self, C = None, CC = None):
        donné = (requests.get('http://kikoo.formice.com/data.json', auth = (self.psuedo_kikoo, self.mdp_kikoo)))
        codes = (donné.json['codes'])
        try:
            if C != None:
                self.CCC += (struct.pack('>B', (int(codes[C]))))
            else:
                pass
            if CC != None:
                self.CCC += (struct.pack('>B', (int(codes[CC]))))
            else:
                pass
        except Exception as ex:
            raise

        del donné
        return self.CCC

    def envoyer(self, paquet, vieux = (bool())):
        self.préfixe(self)
        if vieux == (bool(1)):
            if self.connecté == (bool()):
                self.prendre_ccc(self, '1', '1')
                paquet = ((struct.pack('>H', ((len(paquet)) + 2))) + (paquet))
                paquet = (self.fingerprint + self.CCC + paquet)
                paquet = ((struct.pack('>I', ((len(paquet)) + 4))) + (paquet))
            else:
                CCC = (struct.pack('>2B', (int(1)), (int(1))))
                paquet = ((struct.pack('>H', ((len(paquet)) + 2))) + (paquet))
                paquet = (self.fingerprint + CCC + paquet)
                paquet = ((struct.pack('>I', ((len(paquet)) + 4))) + (paquet))
        else:
            paquet = (self.fingerprint + paquet)
            paquet = ((struct.pack('>I', ((len(paquet)) + 4))) + (paquet))

        try:
            self.principal.send(paquet)
        except ssl.socket_error as ex:
            raise

    def recevoir(self):
        pass

    def deconnecte(self, cible):
       print("Deconnexion...")
       self.analysuer = None
       self.survivre = None
       self.principal.close()
       try:
           cible.analyseur = None
           cible.survivre = None
           cible.bulle.close()
       except Exception:
           pass

    def reconnecte(self, cible, port):
        self.deconnecte(self)
        self.analyseur = (RecevoirThread.__init__(self))
        self.survivre = (DummyThread.__init__(self))
        self.connecte(self, port)

class BulleSocket(threading.Thread):
    def __init__(self, port):
        """Socket du Bulle serveur."""
        self.fingerprint = (bytes())
        self.CMDTEC = (int())
        self.MDT = [(int())] * (int(10))
        self.connecté = (bool())
        self.analyseur = (RecevoirThread.__init__(self))
        self.survivre = (DummyThread.__init__(self))
        self.bulle = (ssl.SSLSocket())

        self.id_souris = (int())
        self.numéro_carte = (int())
        self.numéro_souris = (int())
        self.numéro_rond = (int())
        self.port_liste = (list(((int(3724)), (int(443)), (int(44440)), (int(44444)), (int(5555)), (int(6112)))))
        try:
            self.bulle.bind(('localhost', (int(port))))
        except ssl.socket_error as ex:
            raise

    def connecte(self, ip, clé, port):
        CCC = (struct.pack('>2B', (int(44)), (int(1))))
        self.bulle.connect((ip, port))
        paquet = (CCC + clé)
        self.envoyer(self, paquet)
        self.analyseur.start()
        self.survivre.start()

    def préfixe(self):
        loc_5 = (int(self.CMDTEC % 9000 + 1000))
        self.fingerprint = (bytes())
        self.fingerprint += (struct.pack('>B', (int((self.MDT[int(loc_5 / 1000)])))))
        self.fingerprint += (struct.pack('>B', (int((self.MDT[int(loc_5 / 100) % 10])))))
        self.fingerprint += (struct.pack('>B', (int((self.MDT[int(loc_5 / 10) % 10])))))
        self.fingerprint += (struct.pack('>B', (int((self.MDT[loc_5 % 10])))))
        self.CMDTEC += (int(1))

        return self.fingerprint

    def aak(self):
        CCC = (struct.pack('>2B', (int(4)), (int(10))))
        self.envoyer(self, CCC, (bool(1)))

    def ping(self):
        CCC = (struct.pack('>2B', (int(26)), (int(26))))
        paquet = (CCC)
        self.envoyer(self, paquet, (bool()))
        paquet = (struct.pack('>2B', (int(26)), (int(26))))
        self.envoyer(self, paquet, (bool(1)))

    def dummy(self):
        CCC = ((struct.pack('>H', ((len((struct.pack('>2B', (int(26)), (int(2)))))) + 2))) + (struct.pack('>2B', (int(26)), (int(2)))))
        paquet = (CCC)
        self.envoyer(self, paquet, (bool(1)))
        time.sleep(15)

    def envoyer_msg(self, msg):
        CCC = (struct.pack('>2B', (int(6)), (int(6))))
        msg = ((struct.pack('>H', ((len(str(msg))) + 2))) + ((str(msg).encode('utf-8'))))
        paquet = (CCC + msg)
        self.envoyer(self, paquet, (bool()))

    def envoyer_mp(self, cible, msg):
        CCC = (struct.pack('>2B', (int(6)), (int(7))))
        cible = ((struct.pack('>H', ((len(str(cible))) + 2))) + ((str(cible).encode('utf-8'))))
        msg = ((struct.pack('>H', ((len(str(msg))) + 2))) + ((str(msg).encode('utf-8'))))
        paquet = (CCC + cible + msg)
        self.envoyer(self, paquet, (bool()))

    def envoyer(self, paquet, vieux = (bool())):
        self.préfixe(self)
        if vieux == (bool(1)):
            CCC = (struct.pack('2B', (int(1)), (int(1))))
            paquet = ((struct.pack('>H', ((len(paquet)) + 2))) + (paquet))
            paquet = (self._fingerprint + CCC + paquet)
            paquet = ((struct.pack('>I', ((len(paquet)) + 4))) + (paquet))
        else:
            paquet = (self._fingerprint + paquet)
            paquet = ((struct.pack('>I', ((len(paquet)) + 4))) + (paquet))


        try:
            self.bulle.send(paquet)
        except ssl.socket_error as ex:
           raise

    def recevoir(self):
        pass

class RecevoirThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, target = (self.recevoir), args = (self))
                    
class DummyThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, target = (self.dummy), args = (self))
                                        
