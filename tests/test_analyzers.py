"""Tests for code analyzers."""

import pytest
from src.analyzers import JavaAnalyzer, SQLAnalyzer, MicroservicesAnalyzer, ResiliencyAnalyzer
from src.analyzers.base_analyzer import Severity, Category


class TestJavaAnalyzer:
    """Test Java code analyzer."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = {
            'enabled': True,
            'checks': ['security_vulnerabilities', 'performance_issues', 'design_patterns']
        }
        self.analyzer = JavaAnalyzer(self.config)
    
    def test_can_analyze_java_files(self):
        """Test that analyzer can identify Java files."""
        assert self.analyzer.can_analyze('Test.java')
        assert self.analyzer.can_analyze('com/example/Service.java')
        assert not self.analyzer.can_analyze('test.py')
        assert not self.analyzer.can_analyze('README.md')
    
    def test_sql_injection_detection(self):
        """Test SQL injection vulnerability detection."""
        code = '''
        public class UserService {
            public User findUser(String username) {
                String query = "SELECT * FROM users WHERE username = '" + username + "'";
                Statement stmt = connection.createStatement();
                return stmt.executeQuery(query);
            }
        }
        '''
        
        result = self.analyzer.analyze_file('UserService.java', code)
        
        # Should detect SQL injection vulnerability
        sql_injection_issues = [i for i in result.issues if 'SQL Injection' in i.title]
        assert len(sql_injection_issues) > 0
        assert sql_injection_issues[0].severity == Severity.CRITICAL
        assert sql_injection_issues[0].category == Category.SECURITY
    
    def test_hardcoded_secret_detection(self):
        """Test hardcoded secret detection."""
        code = '''
        public class DatabaseConfig {
            private static final String PASSWORD = "super_secret_password";
            private static final String API_KEY = "sk-1234567890abcdef";
        }
        '''
        
        result = self.analyzer.analyze_file('DatabaseConfig.java', code)
        
        # Should detect hardcoded secrets
        secret_issues = [i for i in result.issues if 'Secret' in i.title]
        assert len(secret_issues) >= 1
        assert secret_issues[0].severity == Severity.MAJOR
        assert secret_issues[0].category == Category.SECURITY
    
    def test_performance_string_concatenation(self):
        """Test string concatenation performance issue detection."""
        code = '''
        public class ReportGenerator {
            public String generateReport(List<String> items) {
                String result = "";
                for (String item : items) {
                    result += item + "\\n";
                }
                return result;
            }
        }
        '''
        
        result = self.analyzer.analyze_file('ReportGenerator.java', code)
        
        # Should detect string concatenation in loop
        perf_issues = [i for i in result.issues if i.category == Category.PERFORMANCE]
        assert len(perf_issues) > 0


class TestSQLAnalyzer:
    """Test SQL code analyzer."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = {
            'enabled': True,
            'checks': ['query_performance', 'sql_injection_prevention', 'index_usage']
        }
        self.analyzer = SQLAnalyzer(self.config)
    
    def test_can_analyze_sql_files(self):
        """Test that analyzer can identify SQL files."""
        assert self.analyzer.can_analyze('schema.sql')
        assert self.analyzer.can_analyze('migration.ddl')
        assert not self.analyzer.can_analyze('test.java')
    
    def test_select_star_detection(self):
        """Test SELECT * usage detection."""
        sql = '''
        SELECT * FROM users WHERE active = 1;
        SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id;
        '''
        
        result = self.analyzer.analyze_file('queries.sql', sql)
        
        # Should detect SELECT * usage
        select_star_issues = [i for i in result.issues if 'SELECT *' in i.title]
        assert len(select_star_issues) >= 1
        assert select_star_issues[0].severity == Severity.MINOR
        assert select_star_issues[0].category == Category.PERFORMANCE
    
    def test_missing_where_clause(self):
        """Test missing WHERE clause detection."""
        sql = '''
        UPDATE users SET last_login = NOW();
        DELETE FROM temp_data;
        '''
        
        result = self.analyzer.analyze_file('dangerous.sql', sql)
        
        # Should detect missing WHERE clauses
        where_issues = [i for i in result.issues if 'WHERE' in i.title]
        assert len(where_issues) >= 1
        assert where_issues[0].severity == Severity.CRITICAL
    
    def test_leading_wildcard_detection(self):
        """Test leading wildcard in LIKE detection."""
        sql = '''
        SELECT * FROM products WHERE name LIKE '%widget%';
        SELECT * FROM users WHERE email LIKE '%@example.com';
        '''
        
        result = self.analyzer.analyze_file('search.sql', sql)
        
        # Should detect leading wildcards
        wildcard_issues = [i for i in result.issues if 'Wildcard' in i.title]
        assert len(wildcard_issues) >= 1
        assert wildcard_issues[0].category == Category.PERFORMANCE


class TestMicroservicesAnalyzer:
    """Test microservices analyzer."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = {
            'enabled': True,
            'checks': ['service_boundaries', 'api_design', 'configuration_management']
        }
        self.analyzer = MicroservicesAnalyzer(self.config)
    
    def test_can_analyze_microservice_files(self):
        """Test file type detection."""
        assert self.analyzer.can_analyze('UserService.java')
        assert self.analyzer.can_analyze('application.yml')
        assert self.analyzer.can_analyze('Dockerfile')
        assert self.analyzer.can_analyze('docker-compose.yml')
    
    def test_missing_api_versioning(self):
        """Test API versioning detection."""
        code = '''
        @RestController
        @RequestMapping("/users")
        public class UserController {
            @GetMapping
            public List<User> getUsers() {
                return userService.findAll();
            }
        }
        '''
        
        result = self.analyzer.analyze_file('UserController.java', code)
        
        # Should detect missing API versioning
        version_issues = [i for i in result.issues if 'Versioning' in i.title]
        assert len(version_issues) >= 1
    
    def test_hardcoded_secret_in_config(self):
        """Test hardcoded secrets in configuration."""
        config = '''
        database:
          host: localhost
          username: admin
          password: super_secret_password
        api:
          key: sk-1234567890abcdef
        '''
        
        result = self.analyzer.analyze_file('application.yml', config)
        
        # Should detect hardcoded secrets
        secret_issues = [i for i in result.issues if 'Secret' in i.title]
        assert len(secret_issues) >= 1
        assert secret_issues[0].severity == Severity.CRITICAL


class TestResiliencyAnalyzer:
    """Test resiliency patterns analyzer."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.config = {
            'enabled': True,
            'patterns': ['circuit_breaker', 'retry_with_backoff', 'timeout', 'health_checks']
        }
        self.analyzer = ResiliencyAnalyzer(self.config)
    
    def test_missing_circuit_breaker(self):
        """Test missing circuit breaker detection."""
        code = '''
        @Service
        public class PaymentService {
            private RestTemplate restTemplate;
            
            public PaymentResponse processPayment(PaymentRequest request) {
                return restTemplate.postForObject("/api/payments", request, PaymentResponse.class);
            }
        }
        '''
        
        result = self.analyzer.analyze_file('PaymentService.java', code)
        
        # Should detect missing circuit breaker
        cb_issues = [i for i in result.issues if 'Circuit Breaker' in i.title]
        assert len(cb_issues) >= 1
        assert cb_issues[0].category == Category.RELIABILITY
    
    def test_missing_timeout_configuration(self):
        """Test missing timeout detection."""
        code = '''
        @Configuration
        public class HttpClientConfig {
            @Bean
            public RestTemplate restTemplate() {
                return new RestTemplate();
            }
        }
        '''
        
        result = self.analyzer.analyze_file('HttpClientConfig.java', code)
        
        # Should detect missing timeout configuration
        timeout_issues = [i for i in result.issues if 'Timeout' in i.title]
        assert len(timeout_issues) >= 1
    
    def test_retry_without_backoff(self):
        """Test retry without backoff detection."""
        code = '''
        @Service
        public class DataService {
            @Retryable(maxAttempts = 3)
            public Data fetchData() {
                return externalService.getData();
            }
        }
        '''
        
        result = self.analyzer.analyze_file('DataService.java', code)
        
        # Should detect retry without backoff
        retry_issues = [i for i in result.issues if 'Backoff' in i.title]
        assert len(retry_issues) >= 1