
import java.math.BigInteger
import java.util.*

class generateRSAKeys(private val bitLength: Int) {
    // Случайно выбираем два простых числа p и q
    private var p = BigInteger.probablePrime(bitLength / 2, Random())
    private var q = BigInteger.probablePrime(bitLength / 2, Random())

    // Вычисляем их произведение n
    private var n = p.multiply(q)

    // Вычисляем функцию Эйлера от n (phi(n))
    private var phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))

    // Генерируем случайное число e, взаимно простое с phi(n)
    private var e = generateRandomE()

    // Вычисляем число d, обратное e по модулю phi(n)
    private var d = e.modInverse(phiN)

    init {
        // Если длина n не соответствует заданной длине битового ключа,
        // перегенерируем значения p, q, n, phi(n), e и d до тех пор, пока n не станет нужной длины
        regenerateNIfNecessary()
    }

    private fun regenerateNIfNecessary() {
        while ((n.bitLength() != bitLength) || (p == q)) {
            p = BigInteger.probablePrime(bitLength / 2, Random())
            q = BigInteger.probablePrime(bitLength / 2, Random())
            n = p.multiply(q)
            phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
            e = generateRandomE()
            d = e.modInverse(phiN)
        }
    }

    private fun generateRandomE(): BigInteger {
        while (true) {
            // Генерируем случайное число потенциальный e
            val potentialE = BigInteger.probablePrime(phiN.bitLength(), Random())
            // Проверяем, что 2 < e < phi(n) и e взаимно просто с phi(n)
            if (potentialE > BigInteger.valueOf(2) && potentialE < phiN && potentialE.gcd(phiN) == BigInteger.ONE) {
                return potentialE
            }
        }
    }

    // Возвращает открытый ключ (e, n) в виде пары BigInteger
    fun getPublicKey(): Pair<BigInteger, BigInteger> {
        return Pair(e, n)
    }

    // Возвращает закрытый ключ (d, n) в виде пары BigInteger
    fun getPrivateKey(): Pair<BigInteger, BigInteger> {
        return Pair(d, n)
    }

    fun getN(): BigInteger {
        return n
    }

    fun getP(): BigInteger {
        return p
    }

    fun getE(): BigInteger {
        return e
    }


}


// Функция для шифрования с использованием открытого ключа
fun encrypt(publicKey: Pair<BigInteger, BigInteger>, plaintext: String): BigInteger {
    val (e, n) = publicKey

    // Преобразуем наш текст в числовое представление
    val messageBytes = plaintext.toByteArray()
    val message = BigInteger(messageBytes)

    // Убедимся, что сообщение не больше n
    if (message >= n) {
        throw IllegalArgumentException("Plaintext too large.")
    }

    // Возводим сообщение в степень e и берем остаток по модулю n
    return message.modPow(e, n)
}

// Функция для дешифрования с использованием закрытого ключа
fun decrypt(privateKey: Pair<BigInteger, BigInteger>, ciphertext: BigInteger): String {
    val (d, n) = privateKey

    // Возводим шифртекст в степень d и берем остаток по модулю n
    val plaintext = ciphertext.modPow(d, n)

    // Преобразуем числовое представление обратно в текст
    return String(plaintext.toByteArray())
}

fun pollardsRho(n: BigInteger): BigInteger {
    var x = BigInteger.valueOf(2)
    var y = BigInteger.valueOf(2)
    var d = BigInteger.ONE

    val g = { num: BigInteger -> num.multiply(num).add(BigInteger.ONE).mod(n) }

    while (d == BigInteger.ONE) {
        x = g(x)
        y = g(g(y))
        d = x.subtract(y).abs().gcd(n)
    }

    return d
}

fun main() {
    // Инициализируем класс RSA и передаем в него длину ключа
    val rsa = generateRSAKeys(64)

    // Получаем открытый и закрытый ключи
    val publicKey = rsa.getPublicKey()
    val privateKey = rsa.getPrivateKey()

    // Текст, который мы хотим зашифровать
    val plaintext = "Hello"

    // Шифруем текст
    val ciphertext = encrypt(publicKey, plaintext)
    println("Encrypted: $ciphertext")

    // Дешифруем текст
    val decryptedText = decrypt(privateKey, ciphertext)
    println("Decrypted: $decryptedText")

    // Пытаемся взломать ключи RSA
    val crackedP = pollardsRho(rsa.getN())

    if (crackedP == rsa.getP()) {
        val crackedQ = rsa.getN() / crackedP
        val crackedPhiN = crackedP.subtract(BigInteger.ONE).multiply(crackedQ.subtract(BigInteger.ONE))
        val crackedD = rsa.getE().modInverse(crackedPhiN)
        val crackedPrivateKey = Pair(crackedD, rsa.getN())

        val crackedText = decrypt(crackedPrivateKey, ciphertext)
        println("Cracked: $crackedText")
    } else {
        println("Failed to crack RSA keys.")
    }

}
