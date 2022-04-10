package io.github.sevenparadigms.abac.configuration

import org.apache.commons.lang3.ObjectUtils
import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.beans.factory.InitializingBean
import org.springframework.boot.context.properties.ConfigurationProperties
import java.io.Serializable

@ConfigurationProperties(prefix = "spring.security.jwt")
data class JwtProperties(
    var headerAuthorize: Boolean,
    var skipTokenValidation: Boolean,
    var publicKey: String,
    var secretKey: String,
    var passwordAlgorithm: String,
    var expiration: Long,
    var iteration: Int,
    var signatureAlgorithm: String,
    var keystorePath: String,
    var keystoreType: String,
    var keystoreAlias: String,
    var keystorePassword: String
) : BeanClassLoaderAware, InitializingBean, Serializable {
    private lateinit var classLoader: ClassLoader

    constructor() : this(false, false, "","","",0,0,"","","","","")

    override fun setBeanClassLoader(classLoader: ClassLoader) {
        this.classLoader = classLoader
    }

    override fun afterPropertiesSet() {
        if (ObjectUtils.isEmpty(headerAuthorize)) headerAuthorize = false
        if (ObjectUtils.isEmpty(skipTokenValidation)) skipTokenValidation = false
        if (ObjectUtils.isEmpty(signatureAlgorithm)) signatureAlgorithm = "HS512"
        if (ObjectUtils.isEmpty(passwordAlgorithm)) passwordAlgorithm = "PBKDF2WithHmacSHA512"
        if (ObjectUtils.isEmpty(expiration)) expiration = 300
        if (ObjectUtils.isEmpty(iteration)) iteration = 512
        if (ObjectUtils.isEmpty(keystoreType)) keystoreType = "PKCS12"
    }
}