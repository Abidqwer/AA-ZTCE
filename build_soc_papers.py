#!/usr/bin/env python3
"""Publication-ready technical papers built from the executed evidence files."""
from pathlib import Path
import json
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT=Path(__file__).resolve().parent;OUT=ROOT/'docs/soc';OUT.mkdir(parents=True,exist_ok=True)
FONT=Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
if FONT.exists():
    pdfmetrics.registerFont(TTFont('Body',str(FONT)))
    pdfmetrics.registerFont(TTFont('BodyBold',str(FONT.with_name('DejaVuSans-Bold.ttf'))))
    pdfmetrics.registerFontFamily('Body',normal='Body',bold='BodyBold',italic='Body',boldItalic='BodyBold')
else:
    pdfmetrics.registerFontFamily('Body',normal='Helvetica',bold='Helvetica-Bold',italic='Helvetica-Oblique',boldItalic='Helvetica-BoldOblique')
    FONT=None
REG='Body' if FONT else 'Helvetica';BOLD='BodyBold' if FONT else 'Helvetica-Bold'
NAVY=colors.HexColor('#10263b');TEAL=colors.HexColor('#007e7d');MUTED=colors.HexColor('#526679');PALE=colors.HexColor('#edf4f7')
styles=getSampleStyleSheet()
styles.add(ParagraphStyle('TitleX',fontName=BOLD,fontSize=25,leading=31,textColor=NAVY,spaceAfter=15))
styles.add(ParagraphStyle('LeadX',fontName=REG,fontSize=12,leading=18,textColor=MUTED,spaceAfter=15))
styles.add(ParagraphStyle('H1X',fontName=BOLD,fontSize=15,leading=20,textColor=NAVY,spaceBefore=13,spaceAfter=9))
styles.add(ParagraphStyle('H2X',fontName=BOLD,fontSize=11,leading=15,textColor=TEAL,spaceBefore=10,spaceAfter=6))
styles.add(ParagraphStyle('BodyX',fontName=REG,fontSize=9.8,leading=15,textColor=NAVY,spaceAfter=9))
styles.add(ParagraphStyle('SmallX',fontName=REG,fontSize=8,leading=11,textColor=MUTED,spaceAfter=6,wordWrap='CJK'))
styles.add(ParagraphStyle('CellX',fontName=REG,fontSize=8.2,leading=12,textColor=NAVY))
styles.add(ParagraphStyle('CellHeadX',fontName=BOLD,fontSize=8.4,leading=12,textColor=colors.white))


def p(text,style='BodyX'):return Paragraph(text,styles[style])
def h(text):return p(text,'H1X')
def sub(text):return p(text,'H2X')
def table(rows,widths):
    cells=[[p(str(cell),'CellHeadX' if i==0 else 'CellX') for cell in row] for i,row in enumerate(rows)]
    t=Table(cells,colWidths=widths,hAlign='LEFT',repeatRows=1)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),NAVY),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),
        ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
        ('LINEBELOW',(0,0),(-1,0),1,TEAL),('LINEBELOW',(0,1),(-1,-1),0.3,colors.HexColor('#d4e0e6'))]))
    return t


def build(name,story,label):
    def furniture(c,doc):
        width,height=A4;c.setStrokeColor(TEAL);c.setLineWidth(2);c.line(44,height-35,width-44,height-35)
        c.setFont(BOLD,8);c.setFillColor(TEAL);c.drawString(44,height-25,'AA-ZTCE / SOC INTEGRATION')
        c.setFont(REG,7);c.setFillColor(MUTED);c.drawString(44,28,label+' | 19 October 2026')
        c.drawRightString(width-44,28,str(doc.page))
    doc=SimpleDocTemplate(str(OUT/name),pagesize=A4,rightMargin=44,leftMargin=44,topMargin=53,bottomMargin=47,
        title=label,author='Abid Yousef',pageCompression=1)
    doc.build(story,onFirstPage=furniture,onLaterPages=furniture)


def positioning(metrics,results,fp):
    s=[p('AA-ZTCE as a preventive<br/>control layer for agent workflows','TitleX'),
       p('Technical positioning, SOC integration, and limits of the present evidence','LeadX'),
       p('<b>Abid Yousef</b> | Architecture originator<br/>Integration edition 0.4.0; archived reference core V0.2.1. AI-assisted implementation and testing. No independent audit or certification.','SmallX'),
       h('1 / Purpose and scope'),
       p('An authenticated autonomous agent can still act outside its approved task, retain data it has already received, or continue using permission after relevant conditions change. AA-ZTCE explores a policy-enforcement boundary that binds access to the execution instance, approved workflow, applicable evidence and current session state.'),
       p('<b>Position:</b> AA-ZTCE complements existing SOC monitoring. It does not replace a SIEM, SOAR platform, staffed SOC, endpoint control, or compliance credential. Its events can add agent-workflow context to those systems; external SOC findings can trigger bounded local containment actions.'),
       table([['Layer','Role in the proposed operating model'],
           ['Agent workflow','Requests an operation using its own signing identity and scoped session.'],
           ['AA-ZTCE gateway','Checks current authority and conditions before releasing a protected response.'],
           ['SIEM / SOC','Correlates control events with endpoint, identity and network evidence.'],
           ['SOAR response','Sends an authenticated, scoped suspension, revocation or reauthentication request.']], [118,389]),
       sub('Implemented boundary'),
       p('The integration edition preserves the archived engine unchanged. Its runtime fork adds a signing-provider seam and a post-authorization masking hook; separate adapters provide SOC events and response. Four scripted workers and a gateway communicate over loopback TCP. Worker seccomp restrictions deny new file opens, new sockets, process creation and process inspection. The trusted controller retains stdio channels. This is a real single-host process boundary, not a hardware enclave, container deployment, remote-attestation system or multi-host transaction.'),
       p('The architectural description is broader than this implementation. Hidden-intent recognition, covert group discovery, cognitive disruption and computational distortion remain unverified. Established zero-trust mechanisms are relevant foundations; novelty and superiority are research questions, not conclusions. [1, 4]','SmallX'),
       PageBreak(),h('2 / SIEM event integration'),
       p('The adapter captures original grant, release, denial and revocation events, and adds checkpoint, identity, task, policy, workflow and SOAR-response records. A SQLite WAL journal stores events before successful protected responses return. Each record is linked to the prior record by a SHA-256 hash. The chain supports integrity checks against a trusted head; it is not resistant to a privileged attacker rewriting the entire local history.'),
       table([['Signal','SOC interpretation and caution'],
           ['Checkpoint failure / pending','A continuation is paused or rejected. Missing evidence or legitimate replanning can explain it; failure alone is not proof of an attack.'],
           ['Denied operation','Records an enforced decision, reason code, workload and session context when available. An out-of-scope request merits investigation.'],
           ['Identity / task change','Explains why previously valid grants became stale. Route expected maintenance separately from threat alerts.'],
           ['Revocation / SOAR response','Links a case and command to the local containment outcome. It does not prove remote queued work was canceled.']], [135,372]),
       sub('Schema and transports'),
       p('Events are projected into ECS 8.17-compatible fields: @timestamp, event.id/action/category/type/outcome/severity, observer.name and user.id. AA-ZTCE-specific session, workflow, domain and case fields remain under aa_ztce. An autonomous workload is represented as user.id for correlation, not as an assertion that a human performed the action. [2]'),
       p('Working exporters cover Splunk HTTP Event Collector, Elasticsearch bulk, generic JSON HTTPS webhooks and RFC 5424/5425 syslog over verified TLS. The outbox retries failures and provides at-least-once delivery; downstream systems should deduplicate event.id. HTTP acceptance does not prove indexed search visibility. Syslog write completion is not an application-level acknowledgment. [3, 5]'),
       sub('Dashboard evidence'),
       p('The package includes a native Splunk dashboard XML, Elasticsearch index template, captured ECS records, and a self-contained correlation dashboard. The dashboard joins real local AA-ZTCE test events with <b>explicitly synthetic</b> EDR and identity telemetry using workload ID and a five-minute window. This is an illustrative correlation, not evidence that a real endpoint was compromised or that a vendor dashboard was deployed.'),
       p('No live Splunk, Elasticsearch or customer SOC instance was available. Protocol-compatible local collectors validated transmission, response handling and retries; platform-side parsing, indexing and search remain pilot acceptance work.','SmallX'),
       PageBreak(),h('3 / SOAR control contract'),
       p('The selected profile is REST over TLS with mutual certificate authentication plus per-client HMAC-SHA256 request signatures. The signed message binds the method, exact path/query, domain audience, timestamp, nonce and hash of the exact body bytes. Client roles constrain both allowed actions and target agents. Certificates establish transport trust; they do not independently grant an action.'),
       table([['Action','Defined effect'],
           ['suspend_session','Sets the checkpoint to PENDING; protected continuation is denied. It cannot revive a revoked session.'],
           ['revoke_session','Invalidates the named session after validating its agent binding.'],
           ['require_reauth','Revokes every current session for the target agent. A separate fresh admission is required; no credentials are issued.'],
           ['disable_agent','Disables the registered identity and revokes its sessions. Re-enable remains a trusted administrative action.']], [135,372]),
       sub('Idempotency and response meaning'),
       p('Each response command carries a command_id and case_id. Completed identical retries use a fresh nonce and return the stored outcome; reusing an ID for a different command is rejected. Nonces and command records are durable. A pending command may be conservatively reapplied following interruption because the supported actions only restrict access. The local gateway serializes enforcement with lifecycle updates.'),
       p('A successful ACK means the local containment action completed. It is not a distributed rollback, a recall of released plaintext, or cancellation of an already-queued external side effect. The original sessions are in memory and do not survive a gateway restart. The OpenAPI 3.1 document and Python signing client are included.'),
       sub('Measured latency, not a service guarantee'),
       p(f"The local test sampled {metrics['samples']} end-to-end signed actions. Median acknowledgment was {metrics['median_ms']:.2f} ms and p95 was {metrics['p95_ms']:.2f} ms, including local TLS/mTLS, HMAC checks, database writes and the gateway response. This single-host result is not a production SLO. A pilot target of p95 at or below one second must be measured under agreed load."),
       p('Operational obligations include managed certificate rotation, client-key custody, bounded retention, queue monitoring, clock integrity, a stable deployment identity and incident escalation. The journal has a configured capacity; exhausted or failed audit persistence prevents a successful protected response. This trade-off favors assurance and can reduce availability during an audit-storage failure.','SmallX'),
       PageBreak(),h('4 / Controlled false-positive measurement'),
       p('The seeded study executes 400 scripted workflows against the reference engine: 120 routine benign workflows, 120 authorized task replans, 120 simulated out-of-scope requests and 40 malicious goals expressed as permitted reads. One checkpoint/continuation evaluation is counted per workflow. Ground-truth labels come from the test scenario; no live LLM or independent labeler participated.'),
       table([['Measure','Observed result'],
           ['Failed checkpoint continuations','240: 120 benign replans and 120 out-of-scope requests.'],
           ['Naive alert: every failure is malicious','120 / 240 benign workflows falsely alerted: 50% FPR.'],
           ['Context rule: scope violation alerts; authorized replan becomes reauthentication','0 / 240 benign workflows falsely alerted: 0% observed FPR.'],
           ['Policy violations detected','120 / 120 out-of-scope requests.'],
           ['All malicious scenarios detected','120 / 160: 75% recall; 40 in-scope malicious goals missed.'],
           ['Legitimate replan recovery','120 / 120 recovered through fresh authoritative admission.']], [251,256]),
       sub('Interpretation'),
       p('Rejecting an old grant after an authoritative task change is policy-correct. The false positive occurs when a SOC rule calls that expected rejection an attack. The context rule was fixed before the run: enforced scope violations create threat alerts; task-version changes trigger workflow review and fresh admission. The improvement therefore measures event interpretation, not improved understanding of an agent\'s intent.'),
       p(f"For 0 observed false alerts among 240 benign workflows, the descriptive 95% Wilson interval is 0 to {100*fp['contextual_fpr_wilson95'][1]:.2f}%. That calculation assumes independent Bernoulli trials; repeated scenario templates are not independent real-world samples. It does not establish a production bound."),
       sub('What this measurement does not establish'),
       p('A checkpoint evaluation here is PENDING/PASS followed immediately by one protected continuation; a denied continuation counts as evaluation failure. This is not a semantic checkpoint detector. The experiment lacks live model reasoning, complex evolving tools, independently authored attacks, realistic base rates and operational incident labels. The 40 permitted malicious reads make the residual limitation explicit: authorization is not intent verification.'),
       PageBreak(),h('5 / Comparative positioning and pilot readiness'),
       table([['Capability','AA-ZTCE integration candidate','Existing SOC stack / organization'],
           ['Workflow authorization','Instance/task/session-bound enforcement at the gateway.','Identity, network and endpoint controls supply complementary evidence.'],
           ['Monitoring and correlation','Emits contextual ECS records; no general-purpose analytics platform.','SIEM searches and correlates multiple telemetry sources.'],
           ['Orchestrated response','Accepts narrowly scoped signed containment commands.','SOAR coordinates cases, approvals and cross-system actions.'],
           ['Operational service','A tested local implementation and evidence package.','A staffed SOC provides monitoring coverage, investigation and escalation.'],
           ['Compliance credentials','The publication does not establish licensing, certification or regulatory approval.','Applicable credentials and compliance evidence belong to verified organizational processes.'],
           ['Formal assurance','Z3 checks selected abstractions; source correctness is not proved.','Independent review and deployment-specific validation remain necessary.']], [105,201,201]),
       sub('Evidence status'),
       p(f"The original test suites and the prior 53 verification checks remain reproducible. The SOC edition recorded {results['passed']}/{results['total']} expected integration outcomes against local TLS collectors and confined agent processes. These counts include negative tests and explicit limitations. They are not an attack-prevention percentage, independent assurance statement, or claim of compatibility with a tested commercial deployment."),
       sub('Next decision'),
       p('A partner sandbox should validate actual SIEM ingestion, identity correlation, mTLS/key operations, held-out workflow labels, response timing and human escalation. Begin with observation and analyst review. Permit containment playbooks only after target binding, permissions and rollback procedures are accepted. A public case note should distinguish measured findings, local assumptions and untested capabilities.'),
       p('<b>References</b><br/>[1] NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final<br/>[2] Elastic ECS event fields: https://www.elastic.co/docs/reference/ecs/ecs-event<br/>[3] Splunk HEC event format: https://help.splunk.com/ (HEC event format documentation)<br/>[4] Archived AA-ZTCE V0.2.1: https://zenodo.org/records/23387780<br/>[5] Syslog protocol / TLS mapping: https://www.rfc-editor.org/rfc/rfc5424 and /rfc/rfc5425<br/>Local evidence: results/soc/; contract: docs/soc/openapi.json.','SmallX')]
    s += [PageBreak(),h('6 / Enterprise alignment and evidence boundaries'),
       p('The enterprise edition adds a fourteen-component, function-level crosswalk in COMPLIANCE.md. It describes how the architecture can contribute to NIST AI RMF Govern, Map, Measure and Manage activities. It is an interpretive crosswalk, not a claim of NIST certification, complete framework coverage, or satisfied organizational obligations.'),
       table([['Pillar','Present implementation and remaining work'],
           ['Risk and insurance','Control records can support underwriting and incident assessment. No measured premium reduction, coverage guarantee or legal due-care finding exists.'],
           ['Workload identity','SPIFFE/SPIRE SVID validation and RFC 8693 delegation are specified roadmap gates. Identity authentication does not independently authorize a task.'],
           ['Data protection','Bounded UTF-8 masking runs after authorization and before response encryption. It detects formatted SSNs, email addresses and Luhn-valid payment card numbers; encoded or contextual sensitive information may pass.'],
           ['Threat context','An explicit enrichment helper uses a pinned MITRE ATLAS catalog and requires a detector, analyst or simulated-evidence reference. Generic denials are not automatically labeled as prompt injection.'],
           ['Deployment tooling','A scoped workflow REST API, Go Terraform provider and single-replica Helm sandbox are supplied. Local protocol tests and chart rendering do not establish successful cluster deployment.'],
           ['Cryptographic agility','A software Ed25519 KeyProvider is wired into the runtime. Hardware custody, protocol-level algorithm negotiation, ML-DSA signatures and ML-KEM key establishment remain planned.']], [115,392]),
       sub('Insurance evidence: what the journal establishes'),
       p('The current journal uses an unkeyed SHA-256 chain. Agent request signatures do not make journal entries digitally signed. Local history can be rewritten by a privileged attacker. A stronger profile needs separately anchored heads, protected signing, independent retention and documented custody. Such measures can improve evidence integrity but do not prove that every relevant action was recorded or that an insurer will lower premiums.'),
       sub('Limits that remain material'),
       p('Redaction does not make all permitted malicious reads harmless, and no new result is claimed for the historical forty in-scope malicious reads. SPIFFE and OAuth do not mathematically eliminate confused-deputy attacks. ML-DSA and ML-KEM serve different purposes; changing one signing provider does not migrate the complete protocol. Independent production validation remains necessary.'),
       p('<b>Additional references</b><br/>NIST AI RMF Core: https://airc.nist.gov/airmf-resources/airmf/5-sec-core/<br/>SPIFFE: https://spiffe.io/docs/latest/spiffe-about/overview/<br/>Token exchange: https://www.rfc-editor.org/rfc/rfc8693<br/>NIST FIPS 204 / 203: https://csrc.nist.gov/pubs/fips/204/final and /203/final<br/>Implementation status and acceptance gates: enterprise/ROADMAP.md; enterprise/DEPLOYMENT.md.','SmallX')]
    build('AA_ZTCE_SOC_Positioning_Paper.pdf',s,'Technical positioning paper')


def pilot():
    s=[p('Joint sandbox pilot proposal','TitleX'),p('AA-ZTCE + BARQ Systems<br/>Agent-workflow controls integrated with SOC operations','LeadX'),
       p('Prepared by Abid Yousef | 19 October 2026<br/>Proposal for discussion. No partnership, engagement, schedule, budget or endorsement has been agreed. No outreach has been sent.','SmallX'),
       h('Objective'),p('Evaluate whether workflow-bound preventive controls and contextual ECS events add useful evidence to an existing SOC without excessive false alarms or disruption. Embed AA-ZTCE in an isolated synthetic workflow and connect it to the partner\'s chosen SIEM and SOAR sandbox. Produce a jointly reviewed technical case note, subject to both parties\' permission.'),
       sub('Why approach BARQ'),p('BARQ publicly describes cybersecurity, infrastructure and managed-service offerings. That combination makes it a reasonable candidate for an integration-led sandbox discussion. This choice does not establish that BARQ has a particular regulatory license, that its compliance fit is stronger than Raya\'s, or that it has agreed to evaluate AA-ZTCE. Source: https://www.barqsystems.com/en (reviewed 19 October 2026).'),
       table([['Included scope','Explicit boundary'],
           ['One isolated agent workflow; four worker identities; synthetic inventory resources.','No production access, customer secrets, payment data or national-security information.'],
           ['ECS ingestion to one actual SIEM sandbox; one correlation dashboard.','Platform access, tokens and certificates supplied through approved partner channels.'],
           ['Signed suspension, revocation and fresh-authentication playbooks.','No automatic credential issuance, privilege elevation or unrestricted tool execution.'],
           ['Labeled legitimate replans and policy violations; permitted-malicious-read controls.','No claim to solve hidden intent or live-model injection until independently tested.']], [253,254]),
       sub('Work sequence - illustrative four-week plan'),
       p('<b>Week 1:</b> Agree threat model, isolation, ownership, certificate trust and data handling; establish the sandbox.<br/><b>Week 2:</b> Validate indexing and correlation; run observation-only workflows and agree labels.<br/><b>Week 3:</b> Enable analyst-approved response actions; test replay, retries, outages and concurrency.<br/><b>Week 4:</b> Run held-out cases, analyze errors and jointly review the case note. Dates and staffing are to be agreed.'),
       PageBreak(),h('Success criteria and responsibilities'),
       table([['Proposed acceptance criterion','Evidence to retain'],
           ['At least 99.5% of emitted test events indexed within 30 seconds under the agreed load.','Gateway sequence / event IDs reconciled with actual SIEM search results; duplicates reported separately.'],
           ['Every tested cross-agent or out-of-scope response request denied.','Signed request traces, expected decisions and no protected release for denied continuations.'],
           ['SOAR acknowledgment p95 <= 1 second at 10 actions/second for 15 minutes.','Client timings, audit records, queue depth and failures. This is a target, not an existing guarantee.'],
           ['No successful protected continuation starting after revocation ACK for that session.','Correlated operation and response timestamps; in-flight and external queued work reported separately.'],
           ['Threat-alert FPR <= 5% on at least 200 independently labeled benign workflows; >= 100 held-out policy violations.','Pre-registered detection rule, full confusion matrix and review of each disagreement. Include at least 40 permitted-malicious-goal controls.'],
           ['SIEM outage causes no silent event loss; retries reconcile after recovery.','Durable outbox, replay/deduplication behavior and audit-capacity failure results.']], [253,254]),
       Spacer(1,10),table([['Party','Proposed responsibilities'],
           ['Abid Yousef / AA-ZTCE','Supply source, threat model, adapters, test harness and baseline evidence; explain assumptions; remediate findings and rerun tests.'],
           ['BARQ technical / SOC team','Provide approved sandbox access, SIEM/SOAR engineering, managed PKI/client scope, independent workflow labeling and analyst review.'],
           ['Joint','Approve success criteria and safe response scope, retain reproducible evidence, assess operational friction and decide whether to publish a case note.']], [125,382]),
       sub('Decision gate'),p('Proceed to a larger pilot only if ingestion, target binding, audit reliability and operational error costs satisfy the agreed criteria. Document failed targets and known in-scope malicious behavior. Any production deployment requires a separate design and assurance review. Commercial terms, intellectual-property treatment and publication permission must be agreed before work begins; no cost or commitment is implied by this proposal.')]
    build('BARQ_AA_ZTCE_Pilot_Proposal.pdf',s,'Sandbox pilot proposal')


def measurement(fp):
    s=[p('Controlled false-positive study','TitleX'),p('Checkpoint continuation events and SOC alert interpretation','LeadX'),
       p('Reference core V0.2.1 | Fixed seed 20261019 | 400 scripted workflows<br/>AI-assisted technical measurement; no live LLM, external assessor or production SOC.','SmallX'),
       h('Question and method'),p('How often does a failure immediately after a checkpoint represent a legitimate workflow change rather than a malicious policy violation? Each workflow begins with a valid identity and grant. The script sets a checkpoint to PENDING and then PASS, and attempts one protected continuation. An authorized replan changes the authoritative task snapshot; continued use of the old grant is correctly denied. A fresh approved admission is then tested.'),
       table([['Scenario','Count','Ground truth / expected behavior'],
           ['Routine permitted read','120','Benign; continuation allowed.'],['Authorized task replan','120','Benign; old grant denied, fresh admission recovers.'],
           ['Restricted resource request','60','Simulated malicious policy violation; denied.'],['External destination request','60','Simulated malicious policy violation; denied.'],
           ['Permitted read with malicious goal','40','Malicious label supplied by scenario; permitted operation can pass.']], [145,60,302]),
       sub('Two alert interpretations'),p('<b>Naive:</b> classify every failed checkpoint continuation as a threat.<br/><b>Context rule fixed before execution:</b> classify enforced scope violations as threat alerts; route authoritative task changes to workflow review and fresh admission. These rules interpret events. They do not infer an agent\'s thoughts or improve the engine\'s underlying permissions.'),
       p('The evaluation counts one opportunity per workflow, not multiple assertions per action. Checkpoint continuation failure is defined operationally as a denied protected operation following the checkpoint. It is not a claim that the core includes a semantic checkpoint classifier.'),
       PageBreak(),h('Results and limits'),
       table([['Metric','Naive interpretation','Context rule'],
           ['True positives / false positives','120 / 120','120 / 0'],['True negatives / false negatives','120 / 40','240 / 40'],
           ['FPR = FP / 240 benign workflows','50%','0% observed'],['Recall = TP / 160 malicious workflows','75%','75%'],
           ['Out-of-scope violations detected','120 / 120','120 / 120'],['Benign replan recovery','120 / 120','120 / 120']], [235,136,136]),
       sub('Failure composition'),p('There were 240 failed continuations: 120 legitimate task replans and 120 simulated out-of-scope requests. Thus 50% of failures were benign replanning events. This fraction is different from the false-positive-rate denominator, which is the 240 benign workflows. Blocking an obsolete grant remains correct even when a threat alert would be wrong.'),
       sub('Statistical caution'),p(f"The context rule produced zero false alerts among 240 benign workflows. Its descriptive 95% Wilson interval is 0 to {100*fp['contextual_fpr_wilson95'][1]:.2f}%. This interval assumes independent Bernoulli trials; repeated templates are correlated and are not a representative production sample. No production false-positive bound is established."),
       sub('Residual weakness'),p('All 40 malicious goals carried out as permitted reads remained undetected. The measured improvement reduces false threat labeling for authorized replans; it does not solve harmful use within approved scope. Overall malicious-scenario recall remains 75% in this constructed mix.'),
       sub('Reproduction and next evaluation'),p('Run <b>python measure_false_positives.py</b>. The fixed seed, complete labels, 400 outcomes and recovery results are in results/soc/false_positive_results.json. Next, use independent labeling and held-out workflows, realistic incident base rates, live-model actions and actual SOC triage. Report operational denial cost separately from false threat alerts.')]
    build('AA_ZTCE_False_Positive_Technical_Note.pdf',s,'Controlled measurement note')


if __name__=='__main__':
    metrics=json.loads((ROOT/'results/soc/soar_latency.json').read_text())
    results=json.loads((ROOT/'results/soc/soc_results.json').read_text())
    fp=json.loads((ROOT/'results/soc/false_positive_results.json').read_text())
    positioning(metrics,results,fp);pilot();measurement(fp)
    from pypdf import PdfReader
    for name,expected in [('AA_ZTCE_SOC_Positioning_Paper.pdf',6),('BARQ_AA_ZTCE_Pilot_Proposal.pdf',2),('AA_ZTCE_False_Positive_Technical_Note.pdf',2)]:
        count=len(PdfReader(OUT/name).pages);print(name,count)
        if count!=expected:raise RuntimeError(f'Unexpected page count for {name}: {count}')
