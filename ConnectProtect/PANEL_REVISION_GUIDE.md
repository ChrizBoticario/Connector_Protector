# ConnectProtect Panel Revision Guide

This guide matches the updated software implementation in version 2.2 and gives you the exact Chapter 4 proof locations, captions, and discussion text.

## 1. Main Revision Position

ConnectProtect is a hybrid malicious URL detection system. The deterministic layer handles trusted or blocked domains through whitelist and blocklist matching. The algorithmic layer performs URL normalization and Levenshtein distance checking for typosquatting. The edge-AI layer is applied only after those filtering stages, where the unknown URL is converted into a numeric feature vector and evaluated by a local weighted linear classifier. This classifier uses a bias value, calibrated feature weights, and a sigmoid probability function to produce a malicious probability score. The final XAI layer then converts the risk score and active model signals into a readable explanation for the user.

## 2. Chapter 1 Location

Location: Chapter 1, Objectives of the Study, after the Specific Objectives list.

Add this paragraph:

The objectives were implemented through a hybrid architecture. The whitelist and blocklist components served as deterministic filtering controls, the Levenshtein distance module served as the algorithmic typosquatting detector, and the edge-AI module served as the local probability classifier. Therefore, the system did not rely on a single detection method. Instead, it combined rule-based filtering, algorithmic similarity analysis, and local model-based inference to generate a final risk level and explanation.

## 3. Chapter 3 Location

Location: Chapter 3, Section 3.2 Project Design, after the list of filtration layers.

Add this paragraph:

The updated system design separated the detection pipeline into four clear stages. First, the content script captured the user's clicked URL before the browser rendered the destination page. Second, the URL was normalized to remove inconsistent formatting and to extract the actual host and path used for analysis. Third, the deterministic and algorithmic modules checked the URL against local whitelist or blocklist entries and measured visual similarity against protected domains through Levenshtein distance. Fourth, if the URL was not resolved by the previous stages, the edge-AI classifier transformed the URL features into a numeric vector and applied the local weight matrix to calculate a probability score. This score became the basis of the final risk level shown in the Cognitive Speed Bump interface.

Location: Chapter 3, Section 3.3 System Architecture, after the Edge-AI Inference paragraph.

Add this paragraph:

In the revised implementation, the edge-AI component is represented by the `CP_EDGE_AI_MODEL` object in `engine.js`. This model contains the classifier identity, threshold, bias, feature order, and feature weights used during local inference. The `cp_buildFeatureVector()` function converts URL observations such as HTTPS status, entropy, URL length, suspicious top-level domain, IP address usage, brand impersonation, suspicious path keywords, and Levenshtein similarity into normalized numeric values. The `cp_scoreFeatures()` function then multiplies these values by their assigned weights, adds the model bias, and applies a sigmoid function to produce the final risk probability. This structure provides concrete evidence that the edge-AI component operates as a local weighted classifier rather than a simple one-rule decision.

## 4. Chapter 4 Proof Map

Use the screenshots below in the same order as the pipeline. Put the code screenshot first, then the UI screenshot.

### A. Start Of Pipeline

Screenshot location:
[content.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\content.js:22>) to [content.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\content.js:38>)

Caption:
Figure 4.X shows the initial interception layer, where ConnectProtect captures the clicked URL and prevents immediate browser navigation.

What it proves:
The browser captures the click event before navigation starts.

### B. URL Routing And Filtering

Screenshot location:
[content.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\content.js:44>) to [content.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\content.js:84>)

Caption:
Figure 4.X shows the deterministic filtering stage, where the intercepted URL is checked against trusted and blocked domains before analysis continues.

What it proves:
The URL is checked against the global whitelist, local whitelist, and blocklist, then passed to the analysis engine.

### C. Edge-AI Model Definition

Screenshot location:
[engine.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\engine.js:108>) to [engine.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\engine.js:166>)

Caption:
Figure 4.X shows the Edge-AI model definition used by ConnectProtect, including the local threshold and calibrated weight matrix.

What it proves:
The local model definition exists, including the threshold, bias, weights, and feature order.

### D. Feature Vector And Scoring

Screenshot location:
[engine.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\engine.js:526>) to [engine.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\engine.js:605>)

Caption:
Figure 4.X shows the feature-vector construction and local weighted inference used to calculate the malicious probability score.

What it proves:
The system converts URL properties into a feature vector and computes the local probability score from the weighted model.

### E. Decision Trace

Screenshot location:
[engine.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\engine.js:558>) to [engine.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\engine.js:572>)

Caption:
Figure 4.X shows the decision trace that documents how the clicked URL moved through extraction, normalization, model scoring, and explanation generation.

What it proves:
The system records the decision path from click capture to threshold comparison and explanation synthesis.

### F. Final XAI Output

Screenshot location:
[content.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\content.js:159>) to [content.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\content.js:316>)

Caption:
Figure 4.X shows the final Cognitive Speed Bump output, where the URL risk score and generated XAI explanation are presented to the user before navigation continues.

What it proves:
The Speed Bump modal shows the risk score, generated XAI narrative, decision trace, model ID, threshold, and user actions.

### G. Popup Proof

Screenshot location:
[popup.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\popup.js:109>) to [popup.js](<C:\Users\CHRIZ BOTICARIO\webfolder\ConnectProtect\popup.js:236>)

Caption:
Figure 4.X shows the popup scanner output, confirming that manual URL scanning and click-based scanning share the same analysis engine.

What it proves:
The manual scan output uses the same engine and shows the same trace-based explanation.

### H. Time And Space Complexity

Use this explanation near the engine screenshots:

The URL analysis pipeline is lightweight because it processes a small set of extracted URL features locally. The preprocessing and feature extraction stages run in linear time relative to the length of the input URL, while the local classifier evaluates a fixed feature vector with a fixed number of weights. This means the inference stage behaves like `O(n)` for URL parsing and feature extraction, followed by `O(1)` model evaluation for the fixed-size weight matrix. The space usage is also small because the system stores only a limited set of feature values, weights, and a short decision trace in memory. This supports the claim that ConnectProtect is suitable for low-resource browser environments.

## 4C. Convert Code Snippets To Tables

The panel request means the code proof should be rewritten as tables in the appendices instead of leaving the code as a pasted block.

### Appendix Table A. Pipeline Verification Table

| Step | File and lines | What the code shows | What it proves in the study |
|---|---|---|---|
| 1 | `content.js` lines 22-38 | Click event is captured in the browser before navigation continues | The system starts with post-click interception |
| 2 | `content.js` lines 44-84 | Global whitelist, user whitelist, and blocklist checks are performed before analysis | Deterministic filtering is working |
| 3 | `engine.js` lines 108-166 | Model card defines threshold, bias, weights, and feature order | A local edge-AI classifier exists |
| 4 | `engine.js` lines 526-605 | Feature vector is built and scored using weighted inference and sigmoid output | URL properties are converted into a probability score |
| 5 | `engine.js` lines 558-572 | Decision path records click capture, normalization, model scoring, and explanation synthesis | The system has a traceable pipeline |
| 6 | `content.js` lines 159-316 | Speed Bump UI shows score, narrative, decision trace, and user actions | The final output is explainable and usable |
| 7 | `popup.js` lines 109-236 | Manual scan uses the same engine and displays the same explanation fields | Popup and click flow share one analysis engine |

### Appendix Table B. Objective Verification Table

| Chapter 1 Objective | Code proof to cite | Result shown in Chapter 4 | Discussion statement to use |
|---|---|---|---|
| Design and develop the browser-based system | `manifest.json`, `background.js`, `content.js`, `popup.js` | Working extension UI, content script, background service worker, and context menu integration | The system was successfully built as a Chromium extension |
| Detect typosquatting using Levenshtein distance | `engine.js` feature extraction section | Typosquatting signals appear in the risk output | The similarity objective was achieved through string-distance comparison |
| Implement edge-based AI scoring | `engine.js` model card and scoring function | Model ID, threshold, linear score, and risk probability appear in the output | The local classifier converted URL features into a risk score |
| Provide explainable AI output | `engine.js` decision trace, `content.js` modal, `popup.js` result card | Generated narrative and decision trace are shown to the user | The system explains the risk instead of showing only a binary block |
| Evaluate the system performance | Chapter 4 test tables and survey results | Confusion matrix, latency values, and ISO/IEC 25010 ratings | The objectives were verified through controlled experiments |

### Appendix Table C. Experiment Verification Table

| Experiment area | Evidence file | Variables recorded | Purpose |
|---|---|---|---|
| Pipeline proof | `content.js`, `engine.js`, `popup.js` | click event, URL extraction, features, model score, trace, XAI output | Shows the end-to-end flow |
| Complexity proof | `engine.js` scoring and feature extraction | URL length, feature count, fixed weight matrix | Shows why the system is lightweight |
| Safe URL testing | Chapter 4 tables in the manuscript | TP, TN, FP, FN, latency, risk score | Verifies correct handling of legitimate URLs |
| Malicious URL testing | Chapter 4 tables in the manuscript | TP, TN, FP, FN, latency, risk score | Verifies correct handling of threats |
| User evaluation | Chapter 4 survey results | Likert responses, ISO/IEC 25010 dimensions | Verifies usability and acceptance |

### Short Appendix Note

If the panel wants tables instead of screenshots, you can say:

The appendix tables summarize each code stage in a verification format. Each row identifies the file, the exact function or lines, the algorithmic step performed, and the research claim it supports. This allows the reviewers to verify the pipeline, the edge-AI inference, the explainable output, and the experiment results without reading the raw source code block by block.

## 5. Chapter 4 Objective Proof

Add this text in Chapter 4 under Results and Discussion, after the project structure discussion:

The objectives stated in Chapter 1 were verified through the implemented code, runtime interface, and test outputs. The first objective, which was to design and develop the browser-based system, was demonstrated by the functional extension components, including the popup dashboard, content script, background service worker, and context menu integration. The second objective, which focused on malicious URL similarity detection, was verified by the Levenshtein-based feature extraction used to compare suspicious URLs with protected brand targets. The third objective, which aimed to implement edge-based AI, was demonstrated by the local classifier in `engine.js`, where URL features were transformed into a numeric vector and scored using a calibrated weight matrix and threshold.

The fourth objective, which required explainable AI output, was achieved through the generated narrative and decision trace shown in both the Speed Bump modal and the popup result card. The fifth objective, which required evaluation of the system, was confirmed by the confusion matrix, risk score distribution, latency measurements, and user assessment results. Taken together, these results show that the system objectives were not only stated in the manuscript but also implemented and verified in the working software.

## 6. Chapter 5 Location

Location: Chapter 5, Conclusions, replace or expand the existing conclusion section.

Add this objective-based conclusion:

Based on the results, the study achieved its objective of developing a browser-integrated post-click malicious URL detection system. The completed extension successfully intercepted clicked URLs, analyzed unknown links locally, displayed risk scores, and provided user actions through the Cognitive Speed Bump interface. The Levenshtein distance objective was achieved through the detection of visually similar domains and typosquatting patterns. The edge-AI objective was achieved through the implementation of a local weighted classifier that transformed URL features into a model-based probability score. The explainability objective was achieved through the generated XAI narrative and decision trace, which translated technical signals into user-readable explanations. Finally, the evaluation objectives were achieved through confusion matrix testing, latency measurement, and ISO/IEC 25010-based user assessment.

## 7. Limitations And Future Work

Location: Chapter 5, Recommendations, add this before or after the existing recommendation list.

Add this text:

The study also recognizes several limitations that should guide future development. First, the current version is limited to post-click URL interception and does not automatically scan URLs typed directly into the browser address bar. Second, the detection engine analyzes URL metadata and lexical structure only; it does not perform deep packet inspection, webpage source-code analysis, SSL certificate validation, or domain age verification. Third, the edge-AI classifier uses a static local weight matrix, meaning future versions should explore dynamic model updates or larger training datasets to improve generalizability. Fourth, the XAI layer generates local explanations from model signals, but future versions may integrate a fully cloud-based LLM or secured Gemini/OpenAI API workflow when API credentials, privacy controls, and institutional approval are available.

## 8. Short Defense Line

Use this if the panel asks how the system works:

ConnectProtect works through a hybrid post-click pipeline. When the user clicks a URL, the extension pauses the navigation and normalizes the link. It first checks deterministic whitelist and blocklist rules. If the URL is unknown, it extracts measurable features such as entropy, URL length, subdomain depth, suspicious TLD, suspicious path keywords, IP address usage, and Levenshtein similarity. These values are converted into a feature vector and processed by a local edge-AI classifier using a weight matrix, bias, and sigmoid probability function. The result becomes the risk score. After that, the XAI layer generates a readable explanation and decision trace, then the Cognitive Speed Bump shows the user the final result and action choices.
