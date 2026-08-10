"""
AI Kavach CRS — CVE Reproduction Benchmark Harness
Runs the AI Kavach CRS pipeline against historical CVEs in real-world codebases.
"""

import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path
from dataclasses import dataclass

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.main import run_pipeline

logger = logging.getLogger(__name__)


@dataclass
class CveBenchmark:
    cve_id: str
    repo_url: str
    vulnerable_commit: str
    build_command: str
    test_command: str
    pov_command: str
    target_file: str


# Sample dataset of historical CVEs for demonstration
BENCHMARK_DATASET = [
    CveBenchmark(
        cve_id="CVE-2015-8126",
        repo_url="https://github.com/glennrp/libpng",
        vulnerable_commit="a4f27f9",  # Vulnerable to buffer overflow in png_set_PLTE
        build_command="./configure && make",
        test_command="make check",
        pov_command="./pngtest bad_palette.png",
        target_file="pngset.c"
    ),
    CveBenchmark(
        cve_id="CVE-2017-9048",
        repo_url="https://github.com/GNOME/libxml2",
        vulnerable_commit="960f0e2",  # Buffer over-read
        build_command="./autogen.sh && make",
        test_command="make check",
        pov_command="./xmllint bad_xml.xml",
        target_file="valid.c"
    )
]


class CveRunner:
    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def run_benchmark(self, cve_id: str = None):
        """Run benchmark on a specific CVE or all in the dataset."""
        targets = [b for b in BENCHMARK_DATASET if b.cve_id == cve_id] if cve_id else BENCHMARK_DATASET
        
        if not targets:
            logger.error(f"No benchmark found for CVE: {cve_id}")
            return

        for benchmark in targets:
            logger.info(f"\n{'='*60}\nBenchmarking {benchmark.cve_id}\n{'='*60}")
            self._process_cve(benchmark)

    def _process_cve(self, benchmark: CveBenchmark):
        """Clone the repo, checkout the vulnerable commit, and run the pipeline."""
        repo_name = benchmark.repo_url.split("/")[-1]
        repo_path = self.workspace_dir / repo_name
        
        # Clone if not exists
        if not repo_path.exists():
            logger.info(f"Cloning {benchmark.repo_url}...")
            subprocess.run(["git", "clone", benchmark.repo_url, str(repo_path)], check=True)
            
        # Checkout vulnerable commit
        logger.info(f"Checking out vulnerable commit: {benchmark.vulnerable_commit}")
        subprocess.run(["git", "-C", str(repo_path), "checkout", "-f", benchmark.vulnerable_commit], check=True)
        subprocess.run(["git", "-C", str(repo_path), "clean", "-fdx"], check=True) # clean working directory

        # Run pipeline
        target_path = str(repo_path / benchmark.target_file)
        
        logger.info(f"Running pipeline on {target_path}...")
        
        try:
            # Note: We run sequentially for benchmarking
            run_pipeline(
                target_path=target_path,
                language="c",
                build_command=f"cd {repo_path} && {benchmark.build_command}",
                test_command=f"cd {repo_path} && {benchmark.test_command}",
                sequential=True
            )
        except Exception as e:
            logger.error(f"Benchmark failed for {benchmark.cve_id}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Kavach CRS - CVE Reproduction Benchmark")
    parser.add_argument("--workspace", default="./benchmark_workspace", help="Directory to clone repos")
    parser.add_argument("--cve", help="Specific CVE ID to test (e.g. CVE-2015-8126)")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    runner = CveRunner(args.workspace)
    runner.run_benchmark(args.cve)
