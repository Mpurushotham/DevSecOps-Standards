
# DevSecOps on Azure Kubernetes Service (AKS)

---

## DevSecOps builds on the practice of DevOps by incorporating security at different stages of a traditional DevOps lifecycle. Some of the benefits of building security in DevOps practices include:

    * Make your applications and systems more secure by providing visibility into security threats and preventing vulnerabilities from reaching deployed environments
    * Increased security awareness with your Development and Operation teams
    * Incorporates automated security processes into your Software Development Lifecycle (SDLC)
    * Reduce cost to remediate by finding security issues early in development and design stages

## When applying DevSecOps to Azure Kubernetes Service (AKS)

there are many considerations for implementing security by different organization roles and teams such as 

### Developers: 

    Building the secure apps running on the AKS (Azure Kubernetes Service) clusters 

### Cloud Platform Engineers: 

    Building the secure AKS clusters Infrastructure

### Operations Team: 

    deploy the containerised apps running on the AKS clusters and govern, monitor the security issues and ensure reliability of the services.

>[!Note] So, this procedure broken out into different DevOps Lifecycle stages with key considerations and embedding security controls and Security best practices.

I will try to includes common processes and tools to incorporate into Azure DevOps - CICD pipelines, opting for easy-to-use built-in tools where available. I would like to strongly emphasize reading this article 
[Build and deploy apps on AKS using DevOps and GitOps] (https://learn.microsoft.com/en-us/azure/architecture/example-scenario/apps/devops-with-aks)


original source link : [DevsecOps+azure AKS visual diagram](https://microsoft.sharepoint.com/:u:/t/AzureArchitectureCenter/ESl-N0a8TAhHtKwF0NDB5jcBMs5aVDWCHw2xUyu6t4oMbA?e=mn0CuY)



![azure_devsecops_diagram](https://github.com/user-attachments/assets/523cf3e1-a238-41d0-9107-68771c65347d)

>[!TIP] This is explicitly references AKS, GitHub, the recommendations mentioned would apply to any container orchestration or CI/CD platform, while the implementation details may vary, most of the concepts and practices mentioned in each stage would still be relevant and applicable.

1. Azure Active Directory (Azure AD) is configured as the identity provider for GitHub. Multi-factor authentication (MFA) should be configured for extra authentication security.
2. Developers use Visual Studio Code or Visual Studio with security extensions enabled to proactively analyze their code for security vulnerabilities.
3. Developers commit application code to a corporate owned and governed GitHub Enterprise repository.
4. GitHub Enterprise integrates automatic security and dependency scanning through GitHub Advanced Security
5. Pull requests trigger continuous integration (CI) builds and automated testing via GitHub actions.
6. The CI build workflow via GitHub actions generates a Docker container image that is stored to Azure Container Registry.
7. Manual approvals can be introduced for deployments to specific environments like production as part of the Continuous Delivery (CD) workflow in GitHub Actions.
8. GitHub Actions enable Continuous Delivery (CD) to Azure Kubernetes Service. GitHub Advanced security can be used to detect secrets, credentials and other sensitive information in your application source and configuration files.
9. Microsoft Defender is used to scan the ACR registry, AKS cluster & Azure Key Vault for security vulnerabilities.
10. Microsoft Defender for containers will scan the container image for known security vulnerabilities upon uploading it to Azure Container Registry.
11. Microsoft Defender for containers can also be used to perform scans of your AKS environment and provides run-time threat protection for your AKS clusters.
12. Microsoft Defender for Azure Key Vault detects harmful and unusual, suspicious attempts to access key vault accounts.
13. Azure Policies can be applied to Azure Container Registry (ACR) and Azure Kubernetes Service (AKS) for policy compliance and enforcement. Common security policies for ACR and AKS are built-in to allow for quick enablement.
14. Azure Key Vault is used to securely inject secrets and credentials into an application at runtime, abstracting sensitive information away from developers.
15. The AKS network policy engine should be configured to secure traffic between application pods using Kubernetes network policies.
16. Continuous monitoring of the AKS cluster can be set up using Azure Monitor & Azure Container Insights to ingest performance metrics and analyze application & security logs.
17. Azure Container Insights is used to retrieve performance metrics and application and cluster logs.
18. Diagnostic and application logs are pulled into an Azure Log Analytics workspace to run log queries.
19. Microsoft Sentinel, which is a SIEM (security information and event management) solution, can be used to ingest and further analyze the AKS cluster logs for any security threats based on defined patterns and rules.
20. Open-Source tools such as OWASP (Open Web Application Security Project) ZAP can be used to do penetration testing for web applications and services.
21. Defender for DevOps, a service available in Defender for Cloud, empowers security teams to manage DevOps security across multi-pipeline environments including GitHub and Azure DevOps.

# DevSecOps standard Life cycle 

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/8eaaf243-880a-4b5e-9811-d03faa9a303f" />

##Azure 
<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/d46dfcd8-14c3-41ba-b308-2cfb5611f208" />
## AWS
<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/c804359a-b878-437d-b58d-b06bf6161e05" />


## DevSecOps lifecyle with software tools can be adopted.

<img width="2696" height="3854" alt="image" src="https://github.com/user-attachments/assets/b40101a2-e149-4d79-9a32-38aa10a118d0" />






