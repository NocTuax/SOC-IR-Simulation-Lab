"""Main script to run SOC IR AI Agent"""

from agent import IRAgent
from sample_alert import SAMPLE_ALERTS

def main():
    print("\n╔════════════════════════════════════════╗")
    print("║   SOC IR AI AGENT v2.0 (OpenAI)       ║")
    print("║   Automated Alert Analysis              ║")
    print("╚════════════════════════════════════════╝\n")
    
    agent = IRAgent()
    
    print("\n📋 Available sample alerts:\n")
    for idx, (name, alert) in enumerate(SAMPLE_ALERTS.items(), 1):
        print(f"{idx}. {name.upper()}")
        print(f"   {alert['rule']['description']}")
        print(f"   Severity: {alert['rule']['level']}/15\n")
    
    print("Select alert to analyze (1-3) or 'all' for all alerts:")
    choice = input("Enter choice: ").strip().lower()
    
    results = []
    
    if choice == "all":
        print("\n🔄 Processing all alerts...\n")
        for name, alert in SAMPLE_ALERTS.items():
            print(f"\n{'='*60}")
            print(f"Processing: {name.upper()}")
            print(f"{'='*60}")
            result = agent.process_alert(alert)
            results.append(result)
            print("\n" + "="*60)
            if result["status"] == "success":
                print("📄 REPORT:\n")
                print(result["report"])
            print("="*60)
    else:
        try:
            alert_idx = int(choice) - 1
            alert_names = list(SAMPLE_ALERTS.keys())
            selected = alert_names[alert_idx]
            
            print(f"\n🔄 Processing {selected.upper()} alert...\n")
            result = agent.process_alert(SAMPLE_ALERTS[selected])
            results.append(result)
            
            print("\n" + "="*60)
            if result["status"] == "success":
                print("📄 FULL REPORT:\n")
                print(result["report"])
            else:
                print(f"❌ {result['message']}")
            print("="*60)
            
        except (ValueError, IndexError):
            print("❌ Invalid choice!")
            return
    
    print("\n✅ Agent processing complete!")

if __name__ == "__main__":
    main()