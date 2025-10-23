"""
Script untuk testing performa algoritma enkripsi
Membandingkan AES, DES, dan RC4 dengan berbagai ukuran file
"""

import os
import time
import secrets
import pandas as pd
import matplotlib.pyplot as plt
from encryption import EncryptionHandler
from datetime import datetime

# Konfigurasi testing
TEST_SIZES = [
    (1024, '1 KB'),           # 1 KB
    (10 * 1024, '10 KB'),     # 10 KB
    (100 * 1024, '100 KB'),   # 100 KB
    (500 * 1024, '500 KB'),   # 500 KB
    (1024 * 1024, '1 MB'),    # 1 MB
    (5 * 1024 * 1024, '5 MB'), # 5 MB
]

ALGORITHMS = ['AES', 'DES', 'RC4']
AES_MODES = ['CBC', 'CTR', 'CFB', 'OFB']
DES_MODES = ['CBC', 'CFB', 'OFB']
ITERATIONS = 10  # Jumlah iterasi per test


class PerformanceTester:
    """Class untuk melakukan performance testing"""
    
    def __init__(self):
        self.results = []
        self.handler = EncryptionHandler()
    
    def generate_test_data(self, size):
        """Generate random data untuk testing"""
        return secrets.token_bytes(size)
    
    def test_algorithm(self, algorithm, mode, data, iterations=10):
        """Test enkripsi dan dekripsi dengan iterasi tertentu"""
        enc_times = []
        dec_times = []
        encrypted_sizes = []
        
        for i in range(iterations):
            # Test encryption
            encrypted_data, key, enc_time = self.handler.encrypt_file(data, algorithm, mode)
            enc_times.append(enc_time)
            encrypted_sizes.append(len(encrypted_data))
            
            # Test decryption
            decrypted_data, dec_time = self.handler.decrypt_file(encrypted_data, key, algorithm, mode)
            dec_times.append(dec_time)
            
            # Verify correctness
            if decrypted_data != data:
                print(f"⚠️ WARNING: Decryption mismatch for {algorithm}-{mode}!")
        
        return {
            'avg_enc_time': sum(enc_times) / len(enc_times),
            'avg_dec_time': sum(dec_times) / len(dec_times),
            'min_enc_time': min(enc_times),
            'max_enc_time': max(enc_times),
            'min_dec_time': min(dec_times),
            'max_dec_time': max(dec_times),
            'avg_encrypted_size': sum(encrypted_sizes) / len(encrypted_sizes),
        }
    
    def run_comprehensive_test(self):
        """Jalankan comprehensive test untuk semua kombinasi"""
        print("=" * 70)
        print("PERFORMANCE TESTING - SECURE FILE EXCHANGE SYSTEM")
        print("=" * 70)
        print(f"Testing started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Iterations per test: {ITERATIONS}")
        print("=" * 70)
        
        for size_bytes, size_label in TEST_SIZES:
            print(f"\n📊 Testing with file size: {size_label}")
            print("-" * 70)
            
            test_data = self.generate_test_data(size_bytes)
            
            # Test AES dengan berbagai mode
            for mode in AES_MODES:
                print(f"  Testing AES-{mode}...", end=' ')
                result = self.test_algorithm('AES', mode, test_data, ITERATIONS)
                self.results.append({
                    'Algorithm': 'AES',
                    'Mode': mode,
                    'File Size': size_label,
                    'File Size (bytes)': size_bytes,
                    'Avg Encryption Time (ms)': result['avg_enc_time'],
                    'Avg Decryption Time (ms)': result['avg_dec_time'],
                    'Min Encryption Time (ms)': result['min_enc_time'],
                    'Max Encryption Time (ms)': result['max_enc_time'],
                    'Min Decryption Time (ms)': result['min_dec_time'],
                    'Max Decryption Time (ms)': result['max_dec_time'],
                    'Encrypted Size (bytes)': result['avg_encrypted_size'],
                    'Overhead (%)': ((result['avg_encrypted_size'] - size_bytes) / size_bytes) * 100,
                    'Throughput Enc (MB/s)': (size_bytes / (1024*1024)) / (result['avg_enc_time'] / 1000),
                    'Throughput Dec (MB/s)': (size_bytes / (1024*1024)) / (result['avg_dec_time'] / 1000),
                })
                print(f"✓ Enc: {result['avg_enc_time']:.3f}ms, Dec: {result['avg_dec_time']:.3f}ms")
            
            # Test DES dengan berbagai mode
            for mode in DES_MODES:
                print(f"  Testing DES-{mode}...", end=' ')
                result = self.test_algorithm('DES', mode, test_data, ITERATIONS)
                self.results.append({
                    'Algorithm': 'DES',
                    'Mode': mode,
                    'File Size': size_label,
                    'File Size (bytes)': size_bytes,
                    'Avg Encryption Time (ms)': result['avg_enc_time'],
                    'Avg Decryption Time (ms)': result['avg_dec_time'],
                    'Min Encryption Time (ms)': result['min_enc_time'],
                    'Max Encryption Time (ms)': result['max_enc_time'],
                    'Min Decryption Time (ms)': result['min_dec_time'],
                    'Max Decryption Time (ms)': result['max_dec_time'],
                    'Encrypted Size (bytes)': result['avg_encrypted_size'],
                    'Overhead (%)': ((result['avg_encrypted_size'] - size_bytes) / size_bytes) * 100,
                    'Throughput Enc (MB/s)': (size_bytes / (1024*1024)) / (result['avg_enc_time'] / 1000),
                    'Throughput Dec (MB/s)': (size_bytes / (1024*1024)) / (result['avg_dec_time'] / 1000),
                })
                print(f"✓ Enc: {result['avg_enc_time']:.3f}ms, Dec: {result['avg_dec_time']:.3f}ms")
            
            # Test RC4
            print(f"  Testing RC4-Stream...", end=' ')
            result = self.test_algorithm('RC4', 'Stream', test_data, ITERATIONS)
            self.results.append({
                'Algorithm': 'RC4',
                'Mode': 'Stream',
                'File Size': size_label,
                'File Size (bytes)': size_bytes,
                'Avg Encryption Time (ms)': result['avg_enc_time'],
                'Avg Decryption Time (ms)': result['avg_dec_time'],
                'Min Encryption Time (ms)': result['min_enc_time'],
                'Max Encryption Time (ms)': result['max_enc_time'],
                'Min Decryption Time (ms)': result['min_dec_time'],
                'Max Decryption Time (ms)': result['max_dec_time'],
                'Encrypted Size (bytes)': result['avg_encrypted_size'],
                'Overhead (%)': ((result['avg_encrypted_size'] - size_bytes) / size_bytes) * 100,
                'Throughput Enc (MB/s)': (size_bytes / (1024*1024)) / (result['avg_enc_time'] / 1000),
                'Throughput Dec (MB/s)': (size_bytes / (1024*1024)) / (result['avg_dec_time'] / 1000),
            })
            print(f"✓ Enc: {result['avg_enc_time']:.3f}ms, Dec: {result['avg_dec_time']:.3f}ms")
        
        print("\n" + "=" * 70)
        print("✅ Testing completed!")
        print("=" * 70)
    
    def save_results(self, output_dir='test_results'):
        """Simpan hasil testing ke file"""
        os.makedirs(output_dir, exist_ok=True)
        
        df = pd.DataFrame(self.results)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save to CSV
        csv_path = os.path.join(output_dir, f'performance_test_{timestamp}.csv')
        df.to_csv(csv_path, index=False)
        print(f"\n📄 Results saved to: {csv_path}")
        
        # Save to Excel dengan multiple sheets
        excel_path = os.path.join(output_dir, f'performance_test_{timestamp}.xlsx')
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='All Results', index=False)
            
            # Summary by algorithm
            summary = df.groupby(['Algorithm', 'Mode']).agg({
                'Avg Encryption Time (ms)': 'mean',
                'Avg Decryption Time (ms)': 'mean',
                'Overhead (%)': 'mean',
                'Throughput Enc (MB/s)': 'mean',
            }).round(3)
            summary.to_excel(writer, sheet_name='Summary')
        
        print(f"📊 Excel report saved to: {excel_path}")
        
        return df
    
    def generate_visualizations(self, df, output_dir='test_results'):
        """Generate visualisasi hasil testing"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 1. Encryption Time Comparison
        plt.figure(figsize=(14, 8))
        for algo in ALGORITHMS:
            data = df[df['Algorithm'] == algo]
            for mode in data['Mode'].unique():
                mode_data = data[data['Mode'] == mode]
                plt.plot(mode_data['File Size'], mode_data['Avg Encryption Time (ms)'], 
                        marker='o', label=f'{algo}-{mode}')
        
        plt.xlabel('File Size')
        plt.ylabel('Encryption Time (ms)')
        plt.title('Encryption Performance Comparison')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'encryption_time_{timestamp}.png'), dpi=300)
        print(f"📈 Encryption chart saved")
        
        # 2. Decryption Time Comparison
        plt.figure(figsize=(14, 8))
        for algo in ALGORITHMS:
            data = df[df['Algorithm'] == algo]
            for mode in data['Mode'].unique():
                mode_data = data[data['Mode'] == mode]
                plt.plot(mode_data['File Size'], mode_data['Avg Decryption Time (ms)'], 
                        marker='s', label=f'{algo}-{mode}')
        
        plt.xlabel('File Size')
        plt.ylabel('Decryption Time (ms)')
        plt.title('Decryption Performance Comparison')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'decryption_time_{timestamp}.png'), dpi=300)
        print(f"📈 Decryption chart saved")
        
        # 3. Overhead Comparison
        plt.figure(figsize=(12, 6))
        overhead_summary = df.groupby(['Algorithm', 'Mode'])['Overhead (%)'].mean().sort_values()
        overhead_summary.plot(kind='barh', color='skyblue', edgecolor='black')
        plt.xlabel('Average Overhead (%)')
        plt.title('Encryption Overhead Comparison')
        plt.grid(True, alpha=0.3, axis='x')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'overhead_{timestamp}.png'), dpi=300)
        print(f"📈 Overhead chart saved")
        
        # 4. Throughput Comparison
        plt.figure(figsize=(14, 6))
        throughput = df.groupby(['Algorithm', 'Mode']).agg({
            'Throughput Enc (MB/s)': 'mean',
            'Throughput Dec (MB/s)': 'mean'
        }).sort_values('Throughput Enc (MB/s)', ascending=False)
        
        throughput.plot(kind='bar', width=0.8)
        plt.xlabel('Algorithm-Mode')
        plt.ylabel('Throughput (MB/s)')
        plt.title('Average Throughput Comparison')
        plt.legend(['Encryption', 'Decryption'])
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, alpha=0.3, axis='y')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'throughput_{timestamp}.png'), dpi=300)
        print(f"📈 Throughput chart saved")
        
        plt.close('all')
    
    def print_summary(self, df):
        """Print summary statistics"""
        print("\n" + "=" * 70)
        print("📊 PERFORMANCE SUMMARY")
        print("=" * 70)
        
        print("\n🏆 FASTEST ENCRYPTION:")
        fastest_enc = df.loc[df['Avg Encryption Time (ms)'].idxmin()]
        print(f"   {fastest_enc['Algorithm']}-{fastest_enc['Mode']}: "
              f"{fastest_enc['Avg Encryption Time (ms)']:.3f}ms "
              f"({fastest_enc['File Size']})")
        
        print("\n🏆 FASTEST DECRYPTION:")
        fastest_dec = df.loc[df['Avg Decryption Time (ms)'].idxmin()]
        print(f"   {fastest_dec['Algorithm']}-{fastest_dec['Mode']}: "
              f"{fastest_dec['Avg Decryption Time (ms)']:.3f}ms "
              f"({fastest_dec['File Size']})")
        
        print("\n💾 LOWEST OVERHEAD:")
        lowest_overhead = df.loc[df['Overhead (%)'].idxmin()]
        print(f"   {lowest_overhead['Algorithm']}-{lowest_overhead['Mode']}: "
              f"{lowest_overhead['Overhead (%)']:.2f}%")
        
        print("\n⚡ HIGHEST THROUGHPUT (Encryption):")
        highest_throughput = df.loc[df['Throughput Enc (MB/s)'].idxmax()]
        print(f"   {highest_throughput['Algorithm']}-{highest_throughput['Mode']}: "
              f"{highest_throughput['Throughput Enc (MB/s)']:.2f} MB/s")
        
        print("\n📈 AVERAGE PERFORMANCE BY ALGORITHM:")
        avg_perf = df.groupby('Algorithm').agg({
            'Avg Encryption Time (ms)': 'mean',
            'Avg Decryption Time (ms)': 'mean',
            'Overhead (%)': 'mean'
        }).round(3)
        print(avg_perf)
        
        print("\n" + "=" * 70)


def main():
    """Main function untuk menjalankan performance test"""
    print("\n🚀 Starting Performance Testing...")
    
    tester = PerformanceTester()
    
    # Run tests
    tester.run_comprehensive_test()
    
    # Save results
    df = tester.save_results()
    
    # Generate visualizations
    tester.generate_visualizations(df)
    
    # Print summary
    tester.print_summary(df)
    
    print("\n✅ All done! Check the 'test_results' folder for detailed reports.")


if __name__ == '__main__':
    main()