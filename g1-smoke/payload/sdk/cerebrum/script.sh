#!/bin/bash

# Run local agent
python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/demo_agent \
  --task "What is the idea of AIOS?"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/metagpt_demo_agent \
  --task "create a 2048 game"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/autogen_demo_agent \
  --task "help me solve a mathematical problem that x^2-4x+3=0"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/test_agent \
  --task "Tell me what is the capital of United States"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/academic_agent \
  --task "What is the latest research on the topic of AI and machine learning?"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/cocktail_mixlogist \
  --task "I want to make a cocktail for a party"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/creation_agent \
  --task "Create a picture of a cat"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/demo_agent \
  --task "Tell me what is the core idea of AIOS"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/festival_card_designer \
  --task "I want to make a festival card for a party"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/language_tutor \
  --task "How to say 'Hello' in French?"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/logo_creator \
  --task "Create a logo for a startup"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/math_agent \
  --task "What is the square root of 16?"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/meme_creator \
  --task "Create a meme for a cat"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/music_composer \
  --task "Create a song for a party"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/story_teller \
  --task "Tell me a story of a princess and a prince"

python cerebrum/run_agent.py \
  --mode local \
  --agent_path cerebrum/example/agents/tech_support_agent \
  --task "I have a problem with my computer where I can't access the internet, what should I do?"

# Run remote agent
python cerebrum/run_agent.py \
  --mode remote \
  --agent_author example \
  --agent_name test_agent \
  --agent_version 0.0.3 \
  --agenthub_url https://app.aios.foundation \
  --task "Tell me what is the capital of United States"

# Upload agent to agenthub
python cerebrum/upload_agent.py \
  --agent_path cerebrum/example/agents/test_agent \
  --agenthub_url https://app.aios.foundation


