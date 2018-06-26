package ch;

import org.apache.commons.io.IOUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.log.NullLogChute;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.KeyStoreX509CredentialAdapter;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

@Controller
public class IdpController {

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    @Value("#{systemProperties['idp.entityId']}")
    private String idpEntityId;

    @Value("#{systemProperties['idp.keyStore.privateKey']}")
    private String idpKeyStorePrivateKey;

    @Value("#{systemProperties['idp.keyStore.certificate']}")
    private String idpKeyStoreCertificate;

    @Value("#{systemProperties['idp.keyStore.password']}")
    private String idpKeyStorePassword;

    @GetMapping("/get")
    public void redirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse, Authentication authentication) throws Exception {

        KeyStore keyStore = buildKeystore();

        HTTPRedirectDeflateDecoder httpRedirectDeflateDecoder = new HTTPRedirectDeflateDecoder(new BasicParserPool());

        BasicSAMLMessageContext reqBasicSAMLMessageContext = new BasicSAMLMessageContext();

        reqBasicSAMLMessageContext.setInboundMessageTransport(new HttpServletRequestAdapter(httpRequest));
        httpRedirectDeflateDecoder.decode(reqBasicSAMLMessageContext);

        AuthnRequest scAuthnRequest = (AuthnRequest) reqBasicSAMLMessageContext.getInboundSAMLMessage();

        Response scResponse = buildResponse(authentication.getName(), scAuthnRequest);

        signSAMLObject(keyStore, scResponse);

        //

        SingleSignOnService smSingleSignOnService = buildSAMLObject(SingleSignOnService.class);
        smSingleSignOnService.setLocation(scAuthnRequest.getAssertionConsumerServiceURL());

        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(httpResponse, false);

        BasicSAMLMessageContext resBasicSAMLMessageContext = new BasicSAMLMessageContext();

        resBasicSAMLMessageContext.setOutboundMessageTransport(outTransport);
        resBasicSAMLMessageContext.setPeerEntityEndpoint(smSingleSignOnService);
        resBasicSAMLMessageContext.setOutboundSAMLMessage(scResponse);

        resBasicSAMLMessageContext.setOutboundMessageIssuer(idpEntityId);
        resBasicSAMLMessageContext.setRelayState(reqBasicSAMLMessageContext.getRelayState());

        VelocityEngine velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());
        velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, NullLogChute.class.getName());
        velocityEngine.init();

        HTTPPostSimpleSignEncoder httpPostSimpleSignEncoder = new HTTPPostSimpleSignEncoder(velocityEngine, "/templates/saml2-post-simplesign-binding.vm", true);

        httpPostSimpleSignEncoder.encode(resBasicSAMLMessageContext);

    }

    private Response buildResponse(String nameId, AuthnRequest scAuthnRequest) {

        Response scResponse = buildSAMLObject(Response.class);

        scResponse.setIssuer(buildIssuer());
        scResponse.setID("_" + UUID.randomUUID().toString());
        scResponse.setIssueInstant(new DateTime());
        scResponse.setInResponseTo(scAuthnRequest.getID());

        // Status
        Status scStatus = buildStatus();
        // ~ Status

        Assertion scAssertion = buildAssertion(nameId, scStatus, idpEntityId, scAuthnRequest);

        scResponse.getAssertions().add(scAssertion);
        scResponse.setDestination(scAuthnRequest.getAssertionConsumerServiceURL());

        scResponse.setStatus(scStatus);

        return scResponse;

    }

    private Status buildStatus() {
        Status scStatus = buildSAMLObject(Status.class);
        StatusCode scStatusCode = buildSAMLObject(StatusCode.class);
        scStatusCode.setValue(StatusCode.SUCCESS_URI);
        scStatus.setStatusCode(scStatusCode);
        return scStatus;
    }

    private Issuer buildIssuer() {
        Issuer scIssuer = buildSAMLObject(Issuer.class);
        scIssuer.setValue(idpEntityId);
        return scIssuer;
    }

    private KeyStore buildKeystore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, idpKeyStorePassword.toCharArray());

        String wrappedCert = "-----BEGIN CERTIFICATE-----\n" + idpKeyStoreCertificate + "\n-----END CERTIFICATE-----";
        byte[] decodedKey = Base64.getDecoder().decode(idpKeyStorePrivateKey.getBytes());

        char[] passwordChars = idpKeyStorePassword.toCharArray();
        Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
        ArrayList<Certificate> certs = new ArrayList<>();
        certs.add(cert);

        byte[] privKeyBytes = IOUtils.toByteArray(new ByteArrayInputStream(decodedKey));

        KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(ks);
        keyStore.setKeyEntry(idpEntityId, privKey, passwordChars, certs.toArray(new Certificate[certs.size()]));

        return keyStore;

    }

    private void signSAMLObject(KeyStore keyStore, SignableSAMLObject signableSAMLObject) throws Exception {

        Credential credential = new KeyStoreX509CredentialAdapter(
            keyStore,
            idpEntityId,
            idpKeyStorePassword.toCharArray());

        Signature signature = buildSAMLObject(Signature.class);

        signature.setSigningCredential(credential);

        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
        signature.setKeyInfo(keyInfoGenerator.generate(credential));

        // should be before Signer.signObject
        signableSAMLObject.setSignature(signature);

        Configuration.getMarshallerFactory().getMarshaller(signableSAMLObject).marshall(signableSAMLObject);
        Signer.signObject(signature);

    }

    private <T> T buildSAMLObject(Class clazz) {
        XMLObjectBuilderFactory xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        QName defaultElementName = null;
        try {
            defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        T o = (T) xmlObjectBuilderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        return o;
    }

    private Assertion buildAssertion(String nameId, Status scStatus, String entityId, AuthnRequest scAuthnRequest) {

        Assertion scAssertion = buildSAMLObject(Assertion.class);

        if (scStatus.getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
            Subject subject = buildSubject(nameId, NameIDType.UNSPECIFIED, scAuthnRequest.getAssertionConsumerServiceURL(), scAuthnRequest.getID());
            scAssertion.setSubject(subject);
        }

        Issuer scIssuer = buildSAMLObject(Issuer.class);
        scIssuer.setValue(entityId);
        scIssuer.setFormat(NameIDType.ENTITY);

        Audience scAudience = buildSAMLObject(Audience.class);
        scAudience.setAudienceURI(scAuthnRequest.getIssuer().getValue());
        AudienceRestriction scAudienceRestriction = buildSAMLObject(AudienceRestriction.class);
        scAudienceRestriction.getAudiences().add(scAudience);

        Conditions scConditions = buildSAMLObject(Conditions.class);
        scConditions.getAudienceRestrictions().add(scAudienceRestriction);
        scAssertion.setConditions(scConditions);

        AuthnStatement scAuthnStatement = buildAuthnStatement(new DateTime(), entityId);

        scAssertion.setIssuer(scIssuer);
        scAssertion.getAuthnStatements().add(scAuthnStatement);

        scAssertion.setID("_" + UUID.randomUUID().toString());
        scAssertion.setIssueInstant(new DateTime());

        return scAssertion;

    }

    private Subject buildSubject(String subjectNameId, String subjectNameIdType, String recipient, String inResponseTo) {

        NameID scNameID = buildSAMLObject(NameID.class);
        scNameID.setValue(subjectNameId);
        scNameID.setFormat(subjectNameIdType);

        Subject scSubject = buildSAMLObject(Subject.class);
        scSubject.setNameID(scNameID);

        SubjectConfirmation scSubjectConfirmation = buildSAMLObject(SubjectConfirmation.class);
        scSubjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData scSubjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class);

        scSubjectConfirmationData.setRecipient(recipient);
        scSubjectConfirmationData.setInResponseTo(inResponseTo);
        scSubjectConfirmationData.setNotOnOrAfter(new DateTime().plusMinutes(8 * 60));
        scSubjectConfirmationData.setAddress(recipient);

        scSubjectConfirmation.setSubjectConfirmationData(scSubjectConfirmationData);

        scSubject.getSubjectConfirmations().add(scSubjectConfirmation);

        return scSubject;

    }

    private AuthnStatement buildAuthnStatement(DateTime authnInstant, String entityID) {

        AuthnContextClassRef scAuthnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
        scAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        AuthenticatingAuthority scAuthenticatingAuthority = buildSAMLObject(AuthenticatingAuthority.class);
        scAuthenticatingAuthority.setURI(entityID);

        AuthnContext scAuthnContext = buildSAMLObject(AuthnContext.class);
        scAuthnContext.setAuthnContextClassRef(scAuthnContextClassRef);
        scAuthnContext.getAuthenticatingAuthorities().add(scAuthenticatingAuthority);

        AuthnStatement scAuthnStatement = buildSAMLObject(AuthnStatement.class);
        scAuthnStatement.setAuthnContext(scAuthnContext);

        scAuthnStatement.setAuthnInstant(authnInstant);

        return scAuthnStatement;

    }

}
