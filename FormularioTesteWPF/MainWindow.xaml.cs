using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace FormularioTesteWPF
{
    public partial class MainWindow : Window
    {
        string privateKey = "-----BEGIN PRIVATE KEY-----\n....\n-----END PRIVATE KEY-----";

        public MainWindow()
        {
            InitializeComponent();
        }

        private async Task AutenticarNaAPI()
        {
            // Obtém a hora atual em UTC e converte para milissegundos
            long horaAtualEmSegundos = (long)DateTime.UtcNow.ToUniversalTime().Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            // Calcula a hora uma hora à frente em milissegundos
            long horaFuturaEmSegundos = horaAtualEmSegundos + 3600;

            string header = "" +
            "{\n" +
                "\"alg\": \"RS256\",\n" +
                "\"typ\": \"JWT\"\n" +
            "}";

            string body = "" +
            "{\n" +
                "\"aud\": \"https://proxy.api.prebanco.com.br/auth/server/v1.1/token\",\n" +
                "\"sub\": \"" + txtClientKey.Text + "\",\n" +
                "\"iat\": \"" + horaAtualEmSegundos + "\",\n" +
                "\"exp\": \"" + horaFuturaEmSegundos + "\",\n" +
                "\"jti\": \"" + horaAtualEmSegundos + "000\",\n" +
                "\"ver\": \"1.1\"\n" +
            "}";

            string jwt = JwtGenerator.RSASHA256(JwtGenerator.Base64UrlEncode(header) + "." + JwtGenerator.Base64UrlEncode(body), privateKey);

            var bearer = await ObterBearerTokenBradesco(jwt);

            txtBearerToken.Text = bearer.access_token;
        }

        public static class RandomStringGenerator
        {
            private static readonly Random random = new Random();
            private static readonly string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            public static string Generate(int length)
            {
                return new string(
                    Enumerable.Repeat(chars, length)
                    .Select(s => s[random.Next(s.Length)])
                    .ToArray()
                );
            }
        }

        private async Task ExecutaRegistroDeCobrancas(string jti)
        {
            try
            {

                string nuCliente = RandomStringGenerator.Generate(10);
                string nuControleParticipante = RandomStringGenerator.Generate(25);

                string cnpj = "31759488000055";
                int carteira = 9;
                string nuNegociacao = "285600000000222652";

                //Este json é/foi fornecido pelo suporte Bradesco.
                var json = "" +
                    "{\"nuCPFCNPJ\": " + cnpj[..8] + "," +
                    "\"filialCPFCNPJ\": 0," +
                    "\"ctrlCPFCNPJ\": " + cnpj.Substring(12, 2) + "," +
                    "\"idProduto\": " + carteira + "," +
                    "\"nuNegociacao\": " + nuNegociacao + "," +
                    "\"nuTitulo\": 0," +
                    "\"nuCliente\": \"" + nuCliente + "\"," +
                    "\"dtEmissaoTitulo\": \"" + DateTime.Now.ToString("dd.MM.yyyy") + "\"," +
                    "\"dtVencimentoTitulo\": \"" + DateTime.Now.AddMonths(1).ToString("dd.MM.yyyy") + "\"," +
                    "\"vlNominalTitulo\": 19.0," +
                    "\"cdEspecieTitulo\": 2," +
                    "\"tipoPrazoDecursoTres\": 30," +
                    "\"tpProtestoAutomaticoNegativacao\": 0," +
                    "\"tpVencimento\": 0," +
                    "\"prazoProtestoAutomaticoNegativacao\": 0," +
                    "\"controleParticipante\": \"" + nuControleParticipante + "\"," +
                    "\"cdPagamentoParcial\": \"N\"," +
                    "\"qtdePagamentoParcial\": 0," +
                    "\"percentualJuros\": 0," +
                    "\"vlJuros\": 0," +
                    "\"qtdeDiasJuros\": 0," +
                    "\"percentualMulta\": 0," +
                    "\"vlMulta\": 0," +
                    "\"qtdeDiasMulta\": 0," +
                    "\"percentualDesconto1\": 0," +
                    "\"vlDesconto1\": 0," +
                    "\"dataLimiteDesconto1\": \"\"," +
                    "\"percentualDesconto2\": 0," +
                    "\"vlDesconto2\": 0," +
                    "\"dataLimiteDesconto2\": \"\"," +
                    "\"percentualDesconto3\": 0," +
                    "\"vlDesconto3\": 0," +
                    "\"dataLimiteDesconto3\": \"\"," +
                    "\"prazoBonificacao\": 0," +
                    "\"percentualBonificacao\": 0," +
                    "\"vlBonificacao\": 0," +
                    "\"dtLimiteBonificacao\": \"\"," +
                    "\"vlAbatimento\": 0," +
                    "\"vlIOF\": 0," +
                    "\"nomePagador\": \"CLIENTE TESTE REGISTRO\"," +
                    "\"logradouroPagador\": \"AVENIDA COPACABANA\"," +
                    "\"nuLogradouroPagador\": \"237\"," +
                    "\"complementoLogradouroPagador\": \"\"," +
                    "\"cepPagador\": 7031," +
                    "\"complementoCepPagador\": 150," +
                    "\"bairroPagador\": \"ALPHAVILLE\"," +
                    "\"municipioPagador\": \"BARUERI\"," +
                    "\"ufPagador\": \"SP\"," +
                    "\"cdIndCpfcnpjPagador\": 1," +
                    "\"nuCpfcnpjPagador\": 45317926882," +
                    "\"endEletronicoPagador\": \"\"," +
                    "\"nomeSacadorAvalista\": \"\"," +
                    "\"logradouroSacadorAvalista\": \"\"," +
                    "\"nuLogradouroSacadorAvalista\": \"\"," +
                    "\"complementoLogradouroSacadorAvalista\": \"\"," +
                    "\"cepSacadorAvalista\": 0," +
                    "\"complementoCepSacadorAvalista\": 0," +
                    "\"bairroSacadorAvalista\": \"\"," +
                    "\"municipioSacadorAvalista\": \"\"," +
                    "\"ufSacadorAvalista\": \"\"," +
                    "\"cdIndCpfcnpjSacadorAvalista\": 0," +
                    "\"nuCpfcnpjSacadorAvalista\": 0," +
                    "\"enderecoSacadorAvalista\": \"\"" +
                    "}";

                json = json.Replace(": ", ":");

                DateTime nowUtc = DateTime.UtcNow;
                string timestamp = nowUtc.ToString("yyyy-MM-ddTHH:mm:sszzz");

                var client = new HttpClient();

                client.DefaultRequestHeaders.Clear();

                //var request = new HttpRequestMessage(HttpMethod.Post, "https://proxy.api.prebanco.com.br/v1/boleto-hibrido/registrar-boleto");
                var request = new HttpRequestMessage(HttpMethod.Post, "https://proxy.api.prebanco.com.br/v1/boleto/registrarBoleto");
                request.Headers.Add("Authorization", "Bearer " + txtBearerToken.Text);
                request.Headers.Add("X-Brad-Nonce", jti);
                request.Headers.Add("X-Brad-Signature", GerarBrandSignature("/v1/boleto/registrarBoleto", json, timestamp, jti, privateKey));
                request.Headers.Add("X-Brad-Timestamp", timestamp);
                request.Headers.Add("X-Brad-Algorithm", "SHA256");
                request.Headers.Add("access-token", txtClientKey.Text);

                var content = new StringContent(json);
                content = new StringContent(json, null, "application/json");
                request.Content = content;

                var response = await client.SendAsync(request);
                //response.EnsureSuccessStatusCode();

                var result = await response.Content.ReadAsStringAsync();

                var requisicaoLog = request.ToString();
                var requisicaoResp = response.ToString();

                txtResultado.Text = result;
                Console.WriteLine(await response.Content.ReadAsStringAsync());

            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine("Erro na requisição HTTP: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro inesperado: " + ex.Message);
            }
        }

        private string GerarBrandSignature(string endpoint, string body, string timestamp, string nonce, string privateKey)
        {
            string brandSignature = "";

            // Na primeira linha do arquivo será inserido o Método HTTP usado na requisição do endpoint a ser requisitado.
            // Exemplo, se você for realizar um “POST” para registro de um boleto, a informação presente na primeira linha, será o método POST.
            brandSignature += "POST\n";

            // Na segunda linha, será recebido o Endpoint da sua chamada
            brandSignature += endpoint + "\n";

            // Na terceira linha do arquivo, serão os Parâmetros da requisição caso eles existam para aquele determinado endpoint.
            // Caso não exista parâmetros, a linha deverá ficar em branco e será pulada utilizando a quebra de linha “\n”.
            brandSignature += "\n";

            // Na sua quarta linha, será inserido o Body da requisição, caso não exista um body para a sua chamada,
            // ela deverá seguir o mesmo modelo do parâmetro, ou seja, deverá ficar em branco e e será pulada utilizando a quebra de linha “\n”.
            brandSignature += body + "\n";

            // Na sua quinta linha de montagem, será inserido o Bearer Token de acesso gerado anteriormente com validade de 1hr.
            brandSignature += txtBearerToken.Text + "\n";

            // Na sexta linha, o valor será o Nonce (valor numérico de no máximo dezoito dígitos, o mesmo usado no header X-Brad-Nonce)
            brandSignature += nonce + "\n";

            // Na sétima linha do arquivo, será inserido o Timestamp, representando o momento da chamada (o mesmo usado no header X-Brad-Timestamp).
            brandSignature += timestamp + "\n";

            // Na oitava e última linha, trará o Algoritmo usado para assinar o JWT, no campo header “X-Brad-Algorithm”, que será o valor: SHA256
            brandSignature += "SHA256";

            // faz a assinatura
            var signed = ComputeSHA256(brandSignature, privateKey);

            // limpa os espaços das extremidades
            signed = signed.Trim();

            return signed;
        }

        public static string ComputeSHA256(string value, string certificate)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(certificate.ToCharArray());
            var data = Encoding.ASCII.GetBytes(value);
            var signedData = Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            return signedData;
        }        

        public async Task<BradescoAutenticacaoResposta> ObterBearerTokenBradesco(string jwt)
        {
            BradescoAutenticacaoResposta resposta = new();

            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, "https://proxy.api.prebanco.com.br/auth/server/v1.1/token");
            var collection = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new("assertion", jwt)
            };
            var content = new FormUrlEncodedContent(collection);
            request.Content = content;
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            string token = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                resposta = System.Text.Json.JsonSerializer.Deserialize<BradescoAutenticacaoResposta>(token);
            }

            return resposta;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            _ = AutenticarNaAPI();
        }

        private void btnRegistrarBoleto_Click(object sender, RoutedEventArgs e)
        {
            _ = btnRegistrarBoleto_ClickAsync();
        }

        private async Task btnRegistrarBoleto_ClickAsync()
        {
            long horaAtualEmSegundos = (long)DateTime.UtcNow.ToUniversalTime().Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMicroseconds;
            await ExecutaRegistroDeCobrancas(horaAtualEmSegundos.ToString());
        }        

        public class BradescoAutenticacaoResposta
        {
            public string access_token { get; set; }
            public string token_type { get; set; }
            public int expires_in { get; set; }

            public override string ToString()
            {
                return "" +
                    "{\n" +
                        "\"access_token\": \"" + access_token + "\",\n" +
                        "\"token_type\": \"" + token_type + "\",\n" +
                        "\"expires_in\": \"" + expires_in + "\"\n" +
                    "}";
            }
        }

        /// <summary>
        /// Mover esta classe para o projeto "framework.mstiCSharp"
        /// </summary>
        public static class JwtGenerator
        {
            public static string RSASHA256(string conteudo, string privateKey)
            {
                // Carregar chave privada a partir do conteúdo PEM
                var rsa = RSA.Create();
                rsa.ImportFromPem(privateKey.ToCharArray());

                string token = conteudo;
                byte[] bytesToSign = Encoding.UTF8.GetBytes(token);
                byte[] signatureBytes = rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                string signature = Base64UrlEncode(signatureBytes);
                return token + "." + signature;
            }

            public static string Base64UrlEncode(string input)
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                return Base64UrlEncode(bytes);
            }

            private static string Base64UrlEncode(byte[] input)
            {
                var output = Convert.ToBase64String(input);
                output = output.Split('=')[0]; // Remove padding characters
                output = output.Replace('+', '-'); // 62nd char of encoding
                output = output.Replace('/', '_'); // 63rd char of encoding
                return output;
            }

        }
    }
}