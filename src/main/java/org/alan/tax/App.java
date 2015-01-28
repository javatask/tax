package org.alan.tax;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyStorePasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.SigningCertSelector;

/**
 * Hello world!
 *
 */
public class App {

    public class DirectPasswordProvider implements KeyStorePasswordProvider, KeyEntryPasswordProvider {

        private String pass;

        public DirectPasswordProvider(String pass) {
            this.pass = pass;
        }

        public char[] getPassword() {
            return pass.toCharArray(); //To change body of generated methods, choose Tools | Templates.
        }

        public char[] getPassword(String arg0, X509Certificate arg1) {
            return pass.toCharArray(); //To change body of generated methods, choose Tools | Templates.
        }

    }

    public class FirstCertificateSelector implements SigningCertSelector {

        public X509Certificate selectCertificate(List<X509Certificate> arg0) {
            return arg0.get(0);
        }
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        App ap = new App();
        ap.signDec();

    }

    public void signDec() throws Exception {

        try {
            //Load document
            File taxDec = new File("taxDeclarationExample.xml");
            if (!taxDec.exists()) {
                System.err.println("Відсутній файл звітності");
                System.exit(-1);
            }

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document ndoc = dBuilder.newDocument();
            Document doc = dBuilder.parse(new FileInputStream(taxDec));
            doc.getDocumentElement().normalize();

            //Load keys and certificate
            KeyingDataProvider kp
                    = new FileSystemKeyStoreKeyingDataProvider("jks", "user.jks",
                            new FirstCertificateSelector(),
                            new DirectPasswordProvider("1"),
                            new DirectPasswordProvider("1"),
                            false);
            XadesSigningProfile p = new XadesBesSigningProfile(kp);
            XadesSigner signer = p.newSigner();

            //What to sign? Document
            DataObjectDesc obj = new DataObjectReference("");
            SignedDataObjects dataObjs = new SignedDataObjects(obj).withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfOrigin());

            //Sign
            signer.sign(dataObjs, doc.getDocumentElement());

            //Save
            TransformerFactory tf = TransformerFactory.newInstance();
            FileOutputStream out = new FileOutputStream(new File(taxDec.getName() + ".sig.xml"));
            tf.newTransformer().transform(
                    new DOMSource(doc),
                    new StreamResult(out));
            out.close();

        } catch (Exception e) {
            System.err.println("Виникла помилка " + e.getMessage());
            System.exit(-1);
        }
    }

}
