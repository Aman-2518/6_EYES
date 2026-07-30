import config


def get_risk_info(service):

    

    return config.RISK_RULES.get(
        service,
        config.RISK_RULES["Unknown Service"]
    )

def calculate_security_score(risks) :
    total_penalty = 0
    for risk in risks:
        total_penalty += risk["score_penalty"]

    return max(0, 100 - total_penalty)
